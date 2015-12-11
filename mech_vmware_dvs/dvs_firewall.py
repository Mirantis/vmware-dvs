# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
from neutron.agent import firewall
from neutron.i18n import _LI
from oslo_log import log as logging

from mech_vmware_dvs import config
from mech_vmware_dvs import util
LOG = logging.getLogger(__name__)

CONF = config.CONF


class DVSFirewallDriver(firewall.FirewallDriver):
    """DVS Firewall Driver.
    """
    def __init__(self):
        self.networking_map = util.create_network_map_from_config(
            CONF.ml2_vmware)
        self.dvs_ports = {}

    def prepare_port_filter(self, port):
        LOG.info(_LI("Called prepare_port_filter"))
        self.dvs_ports.update(port)

    def apply_port_filter(self, port):
        LOG.info(_LI("Called apply_port_filter"))
        self.dvs_ports.update(port)

    def update_port_filter(self, port):
        LOG.info(_LI("Called update_port_filter"))
        self.dvs_ports.update(port)

    def remove_port_filter(self, port):
        LOG.info(_LI("Called remove_port_filter"))

    def filter_defer_apply_on(self):
        LOG.info(_LI("Called filter_defer_apply_on"))

    def filter_defer_apply_off(self):
        LOG.info(_LI("Called filter_defer_apply_off"))

    @property
    def ports(self):
        return self.dvs_ports

    def security_group_updated(self, action_type, sec_group_ids,
                               device_ids=None):
        LOG.debug("Update rules of security group (%s)", sec_group_ids)

    def update_security_group_rules(self, sg_id, sg_rules):
        LOG.debug("Update rules of security group (%s)", sg_id)

    def update_security_group_members(self, sg_id, sg_members):
        LOG.debug("Update members of security group (%s)", sg_id)
