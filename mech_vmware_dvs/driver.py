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

import six

from oslo_log import log
import oslo_messaging
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.i18n import _LI
from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers import mech_agent
from neutron.agent import securitygroups_rpc
from neutron import context

from mech_vmware_dvs import compute_util
from mech_vmware_dvs import config
from mech_vmware_dvs import endpoints
from mech_vmware_dvs import exceptions
from mech_vmware_dvs import util

CONF = config.CONF
LOG = log.getLogger(__name__)

VMWARE_HYPERVISOR_TYPE = 'VMware vCenter Server'


def port_belongs_to_vmware(func):
    @six.wraps(func)
    def _port_belongs_to_vmware(self, context):
        port = context.current
        try:
            try:
                host = port['binding:host_id']
            except KeyError:
                raise exceptions.HypervisorNotFound

            hypervisor = compute_util.get_hypervisors_by_host(
                CONF, host)

            # value for field hypervisor_type collected from VMWare itself,
            # need to make research, about all possible and suitable values
            if hypervisor.hypervisor_type != VMWARE_HYPERVISOR_TYPE:
                raise exceptions.HypervisorNotFound
        except exceptions.ResourceNotFond:
            return False
        return func(self, context)
    return _port_belongs_to_vmware


class VMwareDVSMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Ml2 Mechanism driver for vmware dvs."""

    def __init__(self):
        self.vif_type = util.DVS
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        self.vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                            portbindings.OVS_HYBRID_PLUG: sg_enabled}
        self.context = context.get_admin_context_without_session()
        self.dvs_notifier = util.DVSClientAPI(self.context)
        LOG.info(_LI('DVS_notifier'))
        super(VMwareDVSMechanismDriver, self).__init__(
            util.AGENT_TYPE_DVS,
            self.vif_type,
            self.vif_details)

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})

    def initialize(self):
        self.network_map = util.create_network_map_from_config(CONF.ml2_vmware)
        listener = oslo_messaging.get_notification_listener(
            n_rpc.TRANSPORT,
            targets=[oslo_messaging.Target(topic='vmware_dvs')],
            endpoints=[endpoints.SecurityGroupRuleCreateEndPoint(self),
                       endpoints.SecurityGroupRuleDeleteEndPoint(self)],
            executor='eventlet')
        listener.start()

    def create_network_precommit(self, context):
        self.dvs_notifier.create_network_cast(context.current,
                                              context.network_segments[0])

    def update_network_precommit(self, context):
        self.dvs_notifier.update_network_cast(
            context.current, context.network_segments[0], context.original)

    def delete_network_postcommit(self, context):
        self.dvs_notifier.delete_network_cast(context.current,
                                              context.network_segments[0])

    @port_belongs_to_vmware
    def bind_port(self, context):
        self.dvs_notifier.bind_port_cast(context.network.current,
                                         context.network.network_segments,
                                         context.current)
        # TODO(ekosareva): currently a hack, need to check results from agent
        #                  and store port_key
        for segment in context.network.network_segments:
            context.set_binding(
                segment[driver_api.ID],
                self.vif_type,
                self.vif_details,
                status=n_const.PORT_STATUS_ACTIVE)

    @port_belongs_to_vmware
    def update_port_precommit(self, context):
        if context.current['binding:vif_type'] == 'unbound':
            self.bind_port(context)

    @port_belongs_to_vmware
    def update_port_postcommit(self, context):
        security_group_info = self._get_security_group_info(context)
        self.dvs_notifier.update_postcommit_port_cast(
            context.current, context.original,
            context.network.network_segments[0], security_group_info)

        # TODO(ekosareva): removed one more condition(is it really needed?):
        #                  'dvs_port_key' in port['binding:vif_details']
        if (context.current['binding:vif_type'] == 'unbound' and
                context.current['status'] == n_const.PORT_STATUS_DOWN):
            context._plugin.update_port_status(
                context._plugin_context,
                context.current['id'],
                n_const.PORT_STATUS_ACTIVE)

    @port_belongs_to_vmware
    def delete_port_postcommit(self, context):
        security_group_info = self._get_security_group_info(context)
        self.dvs_notifier.delete_port_cast(context.current, context.original,
                                           context.network.network_segments[0],
                                           security_group_info)

    def _get_security_group_info(self, context):
        current_security_group = set(context.current['security_groups'])
        ports = context._plugin.get_ports(context._plugin_context)
        for p in ports:
            if 'security_group_rules' not in p:
                p['security_group_rules'] = []
            if p['id'] == context.current['id']:
                p['security_groups'] = current_security_group
        port_dict = dict([(p['id'], p) for p in ports])
        sg_info = context._plugin.security_group_info_for_ports(
            context._plugin_context, port_dict)
        return {'devices': sg_info['devices'],
                'security_groups': sg_info['security_groups'],
                'sg_member_ips': sg_info['sg_member_ips']}
