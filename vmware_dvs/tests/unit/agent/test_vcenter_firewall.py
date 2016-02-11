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
import uuid

import mock

from neutron.tests import base

from vmware_dvs.agent.firewalls import vcenter_firewall
from vmware_dvs.utils import security_group_utils as sg_utils

FAKE_PREFIX = {'IPv4': '10.0.0.0/24',
               'IPv6': 'fe80::/48'}
FAKE_IP = {'IPv4': '10.0.0.1',
           'IPv6': 'fe80::1'}

FAKE_SG_RULE_IPV4_PORT = {'ethertype': 'IPv4', 'direction': 'ingress',
                          'port_range_min': 20, 'port_range_max': 20,
                          'protocol': 'tcp'}

FAKE_SG_RULE_IPV6 = {'ethertype': 'IPv6', 'direction': 'egress'}

FAKE_SG_RULE_IPV4_WITH_REMOTE = {'ethertype': 'IPv4', 'direction': 'ingress',
                                 'remote_group_id': '12345'}


class TestDVSFirewallDriver(base.BaseTestCase):

    def setUp(self):
        super(TestDVSFirewallDriver, self).setUp()
        self.dvs = mock.Mock()
        self.use_patch('vmware_dvs.utils.dvs_util'
                       '.create_network_map_from_config',
                       return_value={'physnet1': self.dvs})
        self.firewall = vcenter_firewall.DVSFirewallDriver()
        self.sg_rules = [FAKE_SG_RULE_IPV6, FAKE_SG_RULE_IPV4_WITH_REMOTE]
        self.firewall.sg_rules = {'1234': self.sg_rules}
        self.port = self._fake_port('1234', self.sg_rules)
        self.firewall.dvs_port_map = {self.dvs: set([self.port['id']])}
        self.firewall.dvs_ports = {self.port['device']: self.port}

    def use_patch(self, *args, **kwargs):
        patch = mock.patch(*args, **kwargs)
        self.addCleanup(patch.stop)
        return patch.start()

    def _fake_port(self, sg_id, sg_rules, id=uuid.uuid4()):
        return {'id': id,
                'device': 'tapfake_dev',
                'security_groups': [sg_id],
                'security_group_rules': sg_rules,
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'fixed_ips': [FAKE_IP['IPv4'],
                              FAKE_IP['IPv6']],
                'binding:vif_details': {}
                }

    def test_prepare_port_filter(self):
        port = self._fake_port('12345', [FAKE_SG_RULE_IPV4_PORT,
                                         FAKE_SG_RULE_IPV6])
        with mock.patch.object(self.firewall, '_get_dvs_for_port_id',
                               return_value=self.dvs), \
                mock.patch.object(sg_utils,
                                  'update_port_rules') as update_port:
            self.firewall.prepare_port_filter(port)
            update_port.assert_called_once_with(self.dvs, [port])
            self.assertEqual({port['device']: port}, self.firewall.dvs_ports)

    def test_prepare_port_filter_rules_from_sg(self):
        port = self._fake_port('12345', [])
        with mock.patch.object(self.firewall, '_get_dvs_for_port_id',
                               return_value=self.dvs), \
                mock.patch.object(sg_utils,
                                  'update_port_rules') as update_port:
            self.firewall.sg_rules = {'12345': FAKE_SG_RULE_IPV4_PORT}
            self.firewall.prepare_port_filter(port)
            update_port.assert_called_once_with(self.dvs, [port])
            expected_port = port
            expected_port.update({
                'security_group_rules': [FAKE_SG_RULE_IPV4_PORT]})
            self.assertEqual({port['device']: expected_port},
                             self.firewall.dvs_ports)

    def test_remove_port_filter(self):
        port = self._fake_port('12345', [FAKE_SG_RULE_IPV4_PORT,
                                         FAKE_SG_RULE_IPV6])
        with mock.patch.object(self.firewall, '_get_dvs_for_port_id',
                               return_value=self.dvs), \
                mock.patch.object(sg_utils,
                                  'update_port_rules') as update_port:
            self.firewall.remove_port_filter(port)
            expected_port = port
            expected_port['security_group_rules'] = []
            update_port.assert_called_once_with(self.dvs, [expected_port])
            self.assertNotIn(port['id'], self.firewall.dvs_port_map.values())

    def test_update_security_group_rules(self):
        sg_rules = [FAKE_SG_RULE_IPV6, FAKE_SG_RULE_IPV4_PORT]
        port = self._fake_port(
            '1234', [FAKE_SG_RULE_IPV6])
        self.firewall.dvs_ports = {port['device']: port}
        self.firewall.dvs_port_map = {self.dvs: set([port['id']])}
        with mock.patch.object(sg_utils, 'update_port_rules') as update_port:
            self.firewall.update_security_group_rules('1234', sg_rules)
            expected_port = port
            expected_port['security_group_rules'] = sg_rules
            update_port.assert_called_once_with(self.dvs, [expected_port])
            self.assertEqual({'1234': sg_rules},
                             self.firewall.sg_rules)

    def test_update_security_group_rules_no_action(self):
        sg_rules = [FAKE_SG_RULE_IPV6, FAKE_SG_RULE_IPV4_PORT]
        self.firewall.sg_rules = {'1234': sg_rules}
        self.firewall.update_security_group_rules('1234', sg_rules)
        self.assertEqual({'1234': sg_rules}, self.firewall.sg_rules)

    def test_update_security_group_rules_apply_ip_set(self):
        self.firewall.sg_members = {'12345': {'IPv4': ['192.168.0.3'],
                                              'IPv6': []}}
        with mock.patch.object(sg_utils, 'update_port_rules') as update_port:
            updated_sg_rules = [FAKE_SG_RULE_IPV6, FAKE_SG_RULE_IPV4_PORT,
                                FAKE_SG_RULE_IPV4_WITH_REMOTE]
            self.firewall.update_security_group_rules(
                '1234', updated_sg_rules)
            self.port['security_group_rules'] = updated_sg_rules
            update_port.assert_called_once_with(self.dvs, [self.port])
            updated_sg_rules[2]['ip_set'] = ['192.168.0.3']
            self.assertEqual({'1234': updated_sg_rules},
                             self.firewall.sg_rules)

    def test_update_security_group_members(self):
        sg_members = {'IPv4': ['192.168.0.3'], 'IPv6': []}
        with mock.patch.object(sg_utils, 'update_port_rules') as update_port:
            self.firewall.update_security_group_members('12345', sg_members)
            update_port.assert_called_once_with(self.dvs, [self.port])
            self.assertEqual({'12345': sg_members}, self.firewall.sg_members)
            self.port['security_group_rules'][1]['ip_set'] = ['192.168.0.3']
            self.assertEqual({self.port['device']: self.port},
                             self.firewall.dvs_ports)

    def test_update_security_group_rules_and_members(self):
        sg = {'1234': self.sg_rules}
        sg_members = {'12345': {'IPv4': ['192.168.0.3'], 'IPv6': []}}
        with mock.patch.object(sg_utils, 'update_port_rules') as update_port:
            self.firewall.update_security_group_rules_and_members(sg,
                                                                  sg_members)
            update_port.assert_called_once_with(self.dvs, [self.port])
            self.assertEqual(sg_members, self.firewall.sg_members)
            self.port['security_group_rules'][1]['ip_set'] = ['192.168.0.3']
            self.assertEqual(sg, self.firewall.sg_rules)

    def test__apply_sg_rules_for_port(self):
        self.firewall.sg_rules = {'1234': [FAKE_SG_RULE_IPV6,
                                           FAKE_SG_RULE_IPV4_PORT]}
        with mock.patch.object(sg_utils, 'update_port_rules') as update_port:
            self.firewall._apply_sg_rules_for_port(self.port)
            update_port.assert_called_once_with(self.dvs, [self.port])
            self.assertEqual([FAKE_SG_RULE_IPV6, FAKE_SG_RULE_IPV4_PORT],
                             self.port['security_group_rules'])

    def test__apply_ip_set(self):
        self.firewall.sg_members = {'1234': {'IPv4': ['192.168.0.3'],
                                             'IPv6': []}}
        self.firewall._apply_ip_set(self.sg_rules)
        self.assertIn(FAKE_SG_RULE_IPV6, self.sg_rules)
        FAKE_SG_RULE_IPV4_WITH_REMOTE.update({'ip_set': '192.168.0.3'})
        self.assertIn(FAKE_SG_RULE_IPV4_WITH_REMOTE, self.sg_rules)

    def test__get_dvs_for_port_id(self):
        dvs = self.firewall._get_dvs_for_port_id(self.port['id'])
        self.assertEqual(self.dvs, dvs)

    def test__get_dvs_for_port_id_new_dvs(self):
        port = self._fake_port('1234', self.sg_rules, id=uuid.uuid4())
        new_dvs = mock.Mock()
        with mock.patch('vmware_dvs.utils.dvs_util.create_port_map',
                        return_value={new_dvs: [port['id']]}):
            dvs = self.firewall._get_dvs_for_port_id(port['id'])
            self.assertEqual(new_dvs, dvs)
            self.assertDictSupersetOf({new_dvs: set([port['id']])},
                                      self.firewall.dvs_port_map)

    def test__update_sg_rules_for_ports(self):
        self.firewall.sg_rules = {'1234': [FAKE_SG_RULE_IPV4_WITH_REMOTE,
                                           FAKE_SG_RULE_IPV6],
                                  '4567': [FAKE_SG_RULE_IPV4_PORT,
                                           FAKE_SG_RULE_IPV6]}
        with mock.patch.object(sg_utils, 'update_port_rules') as update_port:
            self.firewall._update_sg_rules_for_ports(['1234', '4567'])
            update_port.assert_called_once_with(self.dvs,
                                                [self.port])
            self.assertEqual([FAKE_SG_RULE_IPV4_WITH_REMOTE,
                              FAKE_SG_RULE_IPV6],
                             self.port['security_group_rules'])

    def test__remove_sg_from_dvs_port(self):
        port = self._fake_port('4567', [FAKE_SG_RULE_IPV6], id=uuid.uuid4())
        with mock.patch.object(self.firewall, '_get_dvs_for_port_id',
                               return_value=self.dvs), \
                mock.patch.object(sg_utils,
                                  'update_port_rules') as update_port:
            self.firewall._remove_sg_from_dvs_port(port)
            update_port.assert_called_once_with(self.dvs, [port])
            self.assertEqual([], port['security_group_rules'])
