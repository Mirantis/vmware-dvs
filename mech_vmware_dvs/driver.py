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


from oslo_log import log

from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers import mech_agent

from mech_vmware_dvs import util

LOG = log.getLogger(__name__)

AGENT_TYPE_DVS = 'VMware distributed vSwitch agent'


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
