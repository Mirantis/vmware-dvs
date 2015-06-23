# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.db import api as db
from neutron.db import securitygroups_db
from oslo_log import log
import oslo_messaging
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.extensions import portbindings
from neutron.openstack.common import lockutils
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api

from mech_vmware_dvs import endpoints
from mech_vmware_dvs import compute_util
from mech_vmware_dvs import config
from mech_vmware_dvs import exceptions
from mech_vmware_dvs import util

CONF = config.CONF
LOG = log.getLogger(__name__)


class VMwareDVSMechanismDriver(driver_api.MechanismDriver):
    """Ml2 Mechanism driver for vmware dvs."""

    vif_type = portbindings.VIF_TYPE_DVS
    vif_details = {
        portbindings.CAP_PORT_FILTER: False}

    def initialize(self):
        self.network_map = util.create_network_map_from_config(CONF.ml2_vmware)
        self._bound_ports = set()

        session = db.get_session()
        rules = session.query(securitygroups_db.SecurityGroupRule).all()
        self.sgr_to_sg = {r['id']: r['security_group_id']for r in rules}

        listener = oslo_messaging.get_notification_listener(
            n_rpc.TRANSPORT,
            targets=[oslo_messaging.Target(topic='vmware_dvs')],
            endpoints=[endpoints.SecurityGroupRuleCreateEndPoint(self),
                       endpoints.SecurityGroupRuleDeleteEndPoint(self),
                       endpoints.SecurityGroupCreateEndPoint(self),
                       endpoints.SecurityGroupDeleteEndPoint(self)],
            executor='eventlet')
        listener.start()

    def create_network_precommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context)
        except exceptions.NoDVSForPhysicalNetwork as e:
            LOG.info(_LI('Network %(id)s not created. Reason: %(reason)s') % {
                'id': context.current['id'],
                'reason': e.message})
        except exceptions.InvalidNetwork:
            pass
        else:
            dvs.create_network(context.current, context.network_segments[0])

    def update_network_precommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context)
        except exceptions.NoDVSForPhysicalNetwork as e:
            LOG.info(_LI('Network %(id)s not updated. Reason: %(reason)s') % {
                'id': context.current['id'],
                'reason': e.message})
        except exceptions.InvalidNetwork:
            pass
        else:
            dvs.update_network(context.current)

    def delete_network_postcommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context)
        except exceptions.NoDVSForPhysicalNetwork as e:
            LOG.info(_LI('Network %(id)s not deleted. Reason: %(reason)s') % {
                'id': context.current['id'],
                'reason': e.message})
        except exceptions.InvalidNetwork:
            pass
        else:
            dvs.delete_network(context.current)

    def update_port_postcommit(self, context):
        if not self._port_belongs_to_vmware(context.current):
            return

        try:
            dvs = self._lookup_dvs_for_context(context.network)
        except exceptions.NoDVSForPhysicalNetwork:
            raise exceptions.InvalidSystemState(details=_(
                'Port %(port_id)s belong to VMWare VM, but there is no '
                'mapping from network %(net_id)s to DVS.') % {
                    'port_id': context.current['id'],
                    'net_id': context.network.current['id']})

        self._update_admin_state_up(dvs, context)

        force = context.original['status'] == 'DOWN'
        self._update_security_groups(dvs, context, force=force)

    def delete_port_postcommit(self, context):
        try:
            self._bound_ports.remove(
                context.current['binding:vif_details']['dvs_port_key'])
        except KeyError:
            pass

    @lockutils.synchronized('vmware_dvs_bind_port', external=True)
    def bind_port(self, context):
        if not self._port_belongs_to_vmware(context.current):
            return
        bound_ports = self._get_bound_ports(context)

        for segment in context.network.network_segments:
            dvs = self._lookup_dvs_for_context(context.network)
            port_key = dvs.get_unbound_port_key(
                context.network.current,
                bound_ports
            )
            vif_details = dict(self.vif_details)
            vif_details['dvs_port_key'] = port_key
            context.set_binding(
                segment[driver_api.ID],
                self.vif_type, vif_details,
                status=n_const.PORT_STATUS_ACTIVE)
            bound_ports.add(port_key)
            self._bound_ports = bound_ports

    def _update_admin_state_up(self, dvs, context):
        try:
            original_admin_state_up = context.original['admin_state_up']
        except KeyError:
            pass
        else:
            current_admin_state_up = context.current['admin_state_up']
            perform = current_admin_state_up != original_admin_state_up
            if perform:
                dvs.switch_port_blocked_state(context.current)

    @lockutils.synchronized('vmware_dvs_update_sg', external=True)
    def _update_security_groups(self, dvs, context, force):
        current_sg = set(context.current['security_groups'])
        if force:
            changed_sg = current_sg
        else:
            original_sg = set(context.original['security_groups'])
            changed_sg = current_sg.symmetric_difference(original_sg)

        if changed_sg or force:
            security_group_info = self._get_security_group_info(
                context, current_sg)
            devices, security_groups, sg_member_ips = security_group_info

            sg_to_update = set()
            ports_to_update = set()

            if context.current['id'] == endpoints.FAKE_PORT_ID:
                sg_to_update = sg_to_update.union(changed_sg)
            else:
                ports_to_update.add(context.current['id'])

            for sg_id, rules in security_groups.items():
                for rule in rules:
                    try:
                        remote_group_id = rule['remote_group_id']
                    except KeyError:
                        pass
                    else:
                        if remote_group_id in changed_sg:
                            sg_to_update.add(sg_id)
                        if sg_id in changed_sg.union(sg_to_update):
                            ip_set = sg_member_ips[remote_group_id][
                                rule['ethertype']]
                            rule['ip_set'] = ip_set

            for id, port in devices.iteritems():
                if (port['binding:vif_type'] == self.vif_type and
                        sg_to_update & set(port['security_groups'])):
                    ports_to_update.add(id)

            if ports_to_update:
                ports = []
                for port_id in ports_to_update:
                    port = devices[port_id]
                    for sec_group_id in port['security_groups']:
                        try:
                            rules = security_groups[sec_group_id]
                        except KeyError:
                            # security_group doesn't has rules
                            pass
                        else:
                            port['security_group_rules'].extend(rules)
                    ports.append(port)
                dvs.update_port_rules(ports)

    def _get_security_group_info(self, context, current_security_group):
        ports = context._plugin.get_ports(context._plugin_context)
        for p in ports:
            if 'security_group_rules' not in p:
                p['security_group_rules'] = []
            if p['id'] == context.current['id']:
                p['security_groups'] = current_security_group
        port_dict = {p['id']: p for p in ports}
        sg_info = context._plugin.security_group_info_for_ports(
            context._plugin_context, port_dict)
        devices = sg_info['devices']
        security_groups = sg_info['security_groups']
        sg_member_ips = sg_info['sg_member_ips']
        return devices, security_groups, sg_member_ips

    def _lookup_dvs_for_context(self, network_context):
        segment = network_context.network_segments[0]
        if segment['network_type'] == constants.TYPE_VLAN:
            physical_network = segment['physical_network']
            try:
                return self.network_map[physical_network]
            except KeyError:
                LOG.debug('No dvs mapped for physical '
                          'network: %s' % physical_network)
                raise exceptions.NoDVSForPhysicalNetwork(
                    physical_network=physical_network)
        else:
            raise exceptions.NotSupportedNetworkType(
                network_type=segment['network_type'])

    def _get_bound_ports(self, context):
        network_id = context.network.current['id']
        ports = context._plugin.get_ports(
            context._plugin_context,
            filters={
                'network_id': [network_id],
                'binding:vif_type': [self.vif_type]
            }
        )
        port_keys = set(self._bound_ports)
        for port in ports:
            try:
                port_keys.add(port['binding:vif_details']['dvs_port_key'])
            except KeyError:
                pass
        return port_keys

    def _port_belongs_to_vmware(self, port):
        try:
            try:
                host = port['binding:host_id']
            except KeyError:
                raise exceptions.HypervisorNotFound

            hypervisor = compute_util.get_hypervisors_by_host(
                CONF, host)

            # value for field hypervisor_type collected from VMWare itself,
            # need to make research, about all possible and suitable values
            if hypervisor.hypervisor_type != 'VMware vCenter Server':
                raise exceptions.HypervisorNotFound
        except exceptions.ResourceNotFond:
            return False

        return True
