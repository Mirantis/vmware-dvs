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

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.i18n import _LI
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers import mech_agent

from mech_vmware_dvs import compute_util
from mech_vmware_dvs import config
from mech_vmware_dvs import exceptions

from mech_vmware_dvs import util

LOG = log.getLogger(__name__)
CONF = config.CONF

AGENT_TYPE_DVS = 'VMware distributed vSwitch agent'


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
            if hypervisor.hypervisor_type != 'VMware vCenter Server':
                raise exceptions.HypervisorNotFound
        except exceptions.ResourceNotFond:
            return False
        return func(self, context)
    return _port_belongs_to_vmware


class VMwareDVSMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Ml2 Mechanism driver for vmware dvs."""

    def __init__(self):
        self.vif_type = 'dvs'
        self.vif_details = {portbindings.CAP_PORT_FILTER: False}
        super(VMwareDVSMechanismDriver, self).__init__(
            util.AGENT_TYPE_DVS,
            self.vif_type,
            self.vif_details)

    def get_allowed_network_types(self, agent):
        return (agent['configurations'].get('tunnel_types', []) +
                [constants.TYPE_VLAN])

    def get_mappings(self, agent):
        return agent['configurations'].get('bridge_mappings', {})

    # Return this methods for sometime
    @util.wrap_retry
    @port_belongs_to_vmware
    def update_port_precommit(self, context):
        if context.current['binding:vif_type'] == 'unbound':
            self.bind_port(context)

    @util.wrap_retry
    @port_belongs_to_vmware
    def update_port_postcommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context.network)
        except exceptions.NotSupportedNetworkType as e:
            LOG.info(_LI('Port %(id)s not updated. Reason: %(reason)s') % {
                'id': context.current['id'],
                'reason': e.message})
        except exceptions.NoDVSForPhysicalNetwork:
            raise exceptions.InvalidSystemState(details=_(
                'Port %(port_id)s belong to VMWare VM, but there is no '
                'mapping from network %(net_id)s to DVS.') % {
                    'port_id': context.current['id'],
                    'net_id': context.network.current['id']})
        else:
            self._update_admin_state_up(dvs, context)

            force = context.original['status'] == n_const.PORT_STATUS_DOWN
            self._update_security_groups(dvs, context, force=force)
            if (context.current['binding:vif_type'] == 'unbound' and
                context.current['status'] == n_const.PORT_STATUS_DOWN):
                context._plugin.update_port_status(
                    context._plugin_context,
                    context.current['id'],
                    n_const.PORT_STATUS_ACTIVE)

    @util.wrap_retry
    @port_belongs_to_vmware
    def delete_port_postcommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context.network)
        except exceptions.NoDVSForPhysicalNetwork:
            raise exceptions.InvalidSystemState(details=_(
                'Port %(port_id)s belong to VMWare VM, but there is no '
                'mapping from network %(net_id)s to DVS.') % {
                    'port_id': context.current['id'],
                    'net_id': context.network.current['id']})
        self._update_security_groups(dvs, context, force=True)
        dvs.release_port(context.current)

    @util.wrap_retry
    @port_belongs_to_vmware
    def bind_port(self, context):
        for segment in context.network.network_segments:
            dvs = self._lookup_dvs_for_context(context.network)
            dvs.book_port(context.network.current, context.current['id'])
            vif_details = dict(self.vif_details)
            context.set_binding(
                segment[driver_api.ID],
                self.vif_type, vif_details,
                status=n_const.PORT_STATUS_ACTIVE)

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
