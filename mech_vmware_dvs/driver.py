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

import abc

import six
from oslo_log import log
from oslo_concurrency import lockutils
import oslo_messaging
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron import manager
from neutron.extensions import portbindings
from neutron.i18n import _LI, _
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api, driver_context
from neutron.context import Context

from mech_vmware_dvs import config
from mech_vmware_dvs import exceptions
from mech_vmware_dvs import util

CONF = config.CONF
LOG = log.getLogger(__name__)

FAKE_PORT_ID = 'fake_id'


@six.add_metaclass(abc.ABCMeta)
class EndPointBase(object):

    def __init__(self, driver):
        self.driver = driver

    @abc.abstractmethod
    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        pass

    def update_security_group(self, ctxt, security_group_id):
        plugin_context = Context.from_dict(ctxt)
        plugin = manager.NeutronManager.get_plugin()
        fake_network = {
            'id': 'fake'
        }
        fake_port = {
            'id': FAKE_PORT_ID,
            'security_groups': [security_group_id]
        }
        context = driver_context.PortContext(
            plugin, plugin_context, fake_port, fake_network, None, None
        )
        for dvs in self.driver.network_map.values():
            self.driver._update_security_groups(dvs, context, force=True)


class SecurityGroupRuleCreateEndPoint(EndPointBase):
    filter_rule = oslo_messaging.NotificationFilter(
        publisher_id='network.manager',
        event_type=r'security_group_rule\.create\.end')

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        security_group_id = payload['security_group_rule']['security_group_id']
        self.update_security_group(ctxt, security_group_id)


class SecurityGroupRuleDeleteEndPoint(EndPointBase):
    filter_rule = oslo_messaging.NotificationFilter(
        publisher_id='network.manager',
        event_type=r'security_group_rule\.delete\.(start|end)')

    sgr_to_sg = {}

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        security_group_rule_id = payload['security_group_rule_id']
        if event_type.endswith('start'):
            security_group_id = self.get_security_group_for(
                ctxt,
                security_group_rule_id)
            self.sgr_to_sg[security_group_rule_id] = security_group_id
        else:
            security_group_id = self.sgr_to_sg.pop(security_group_rule_id)
            self.update_security_group(ctxt, security_group_id)

    def get_security_group_for(self, ctxt, security_group_rule_id):
        plugin_context = Context.from_dict(ctxt)
        plugin = manager.NeutronManager.get_plugin()
        rule = plugin.get_security_group_rule(plugin_context,
                                              security_group_rule_id)
        return rule['security_group_id']


class VMwareDVSMechanismDriver(driver_api.MechanismDriver):
    """Ml2 Mechanism driver for vmware dvs."""

    vif_type = portbindings.VIF_TYPE_DVS
    vif_details = {
        portbindings.CAP_PORT_FILTER: False}

    def initialize(self):
        self.network_map = util.create_network_map_from_config(CONF.ml2_vmware)
        self._bound_ports = set()
        listener = oslo_messaging.get_notification_listener(
            n_rpc.TRANSPORT,
            targets=[oslo_messaging.Target(topic='vmware_dvs')],
            endpoints=[SecurityGroupRuleCreateEndPoint(self),
                       SecurityGroupRuleDeleteEndPoint(self)],
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

        force = context.original['status'] == 'DOWN'
        try:
            self._update_admin_state_up(dvs, context, force=force)
        except (exceptions.VMNotFound, exceptions.PortNotFound):
            # until port are not bind to any VM it doesn't exist
            # so we can ignore status change
            pass
        self._update_security_groups(dvs, context, force=force)

    def delete_port_postcommit(self, context):
        try:
            self._bound_ports.remove(
                context.current['binding:vif_details']['dvs_port_key'])
        except KeyError:
            pass

    def _update_admin_state_up(self, dvs, context, force):
        current_admin_state_up = context.current['admin_state_up']
        if force:
            perform = True
        else:
            original_admin_state_up = context.original['admin_state_up']
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

            if context.current['id'] == FAKE_PORT_ID:
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
        return port['binding:vif_type'] == self.vif_type
