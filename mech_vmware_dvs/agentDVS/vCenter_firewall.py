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
        self.sg_rules = {}
        # Map for known port and dvs it is connected to.
        self.dvs_port_map = {}

    @util.wrap_retry
    def prepare_port_filter(self, port):
        self.dvs_ports[port['device']] = port
        self._apply_sg_rules_for_ports(port)
        LOG.info(_LI("Applied security group rules for port %s"), port['id'])

    def apply_port_filter(self, port):
        self.dvs_ports[port['device']] = port
        # Called for setting port in dvs_port_map
        self._get_dvs_for_port_id(port['id'])

    @util.wrap_retry
    def update_port_filter(self, port):
        self.dvs_ports[port['device']] = port
        self._apply_sg_rules_for_ports(port)
        LOG.info(_LI("Updated security group rules for port %s"), port['id'])

    def remove_port_filter(self, port):
        self.dvs_ports.pop(port['device'], None)

    def filter_defer_apply_on(self):
        LOG.info(_LI("Called filter_defer_apply_on"))

    def filter_defer_apply_off(self):
        LOG.info(_LI("Called filter_defer_apply_off"))

    @property
    def ports(self):
        return self.dvs_ports

    @util.wrap_retry
    def update_security_group_rules(self, sg_id, sg_rules):
        if sg_id in sg_rules and self.sg_rules[sg_id] == sg_rules:
            return
        self.sg_rules[sg_id] = sg_rules
        self._update_sg_rules_for_ports(sg_id)
        LOG.debug("Update rules of security group (%s)", sg_id)

    @util.wrap_retry
    def update_security_group_members(self, sg_id, sg_members):
        updated = False
        for sg, rules in self.sg_rules.items():
            for rule in rules:
                if rule.get('remote_group_id') == sg_id:
                    ethertype = rule['ethertype']
                    if (sg_members.get(ethertype)
                            and rule.get('ip_set') != sg_members[ethertype]):
                        rule['ip_set'] = sg_members[rule['ethertype']]
                        updated = True
        if updated:
            self._update_sg_rules_for_ports(sg_id)
        LOG.debug("Update members of security group (%s)", sg_id)

    def _apply_sg_rules_for_ports(self, port):
        dev = port['device']
        sg_rules = 'security_group_rules'
        for sg in port['security_groups']:
            if sg in self.sg_rules.keys():
                if (port['id'] not in self.dvs_port_map.keys()
                        or self.dvs_ports[dev][sg_rules] != self.sg_rules[sg]):
                    port['security_group_rules'] = self.sg_rules[sg]
                    dvs = self._get_dvs_for_port_id(port['id'])
                    dvs.update_port_rules([port])

    def _get_dvs_for_port_id(self, port_id):
        if port_id not in self.dvs_port_map.keys():
            port_map = util.create_port_map(self.networking_map.values())
        else:
            port_map = self.dvs_port_map
        for dvs, port_list in port_map.iteritems():
            if port_id in port_list:
                if dvs not in self.dvs_port_map:
                    self.dvs_port_map[dvs] = []
                self.dvs_port_map[dvs].append(port_id)
                return dvs

    def _update_sg_rules_for_ports(self, sg_id):
        ports_to_update = []
        for port in self.dvs_ports.values():
            if sg_id in port['security_groups']:
                port['security_group_rules'] = self.sg_rules[sg_id]
                ports_to_update.append(port)
        port_ids = {p['id']: p for p in ports_to_update}
        for dvs, port_list in self.dvs_port_map.iteritems():
            ids = [e for e in port_list if e in port_ids.keys()]
            p = []
            for id in ids:
                p.append(port_ids[id])
            if p:
                dvs.update_port_rules(p)
