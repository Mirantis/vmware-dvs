#    Copyright 2015 Mirantis, Inc.
#    All Rights Reserved.
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
#

import mock
from neutron.plugins.common import constants
from neutron.tests import base

from mech_vmware_dvs import endpoints
from mech_vmware_dvs.agentDVS import dvs_neutron_agent
from mech_vmware_dvs import exceptions
from mech_vmware_dvs import util

NOT_SUPPORTED_TYPES = [
    constants.TYPE_FLAT,
    constants.TYPE_GRE,
    constants.TYPE_LOCAL,
    constants.TYPE_VXLAN,
    constants.TYPE_NONE]


VALID_HYPERVISOR_TYPE = 'VMware vCenter Server'
INVALID_HYPERVISOR_TYPE = '_invalid_hypervisor_'


class FAKE_SECURITY_GROUPS(object):
    NEW = 'new_sg'
    CONSTANT = 'constant_sg'
    REMOVED = 'removed_sg'


CONSTANT_SG_RULE = {'constant rule': 'some_rule'}


class DVSAgentTestCase(base.BaseTestCase):

    def setUp(self):
        class TestDVSAgent(dvs_neutron_agent.DVSAgent):
            def __init__(self, network_map):
                self.network_map = network_map

        super(DVSAgentTestCase, self).setUp()
        self.dvs = mock.Mock()
        # mock DVSAgent.__init__() method
        self.agent = TestDVSAgent({'physnet1': self.dvs})
        test_port_data = self._create_port_context()
        self.port_context = test_port_data[0]
        self.sg_info = test_port_data[1]

    def test_look_up_dvs_failed(self):
        for type_ in NOT_SUPPORTED_TYPES:
            self.assertRaisesRegexp(exceptions.NotSupportedNetworkType,
                                    "VMWare DVS driver don't support %s "
                                    "network" % type_,
                                    self.agent._lookup_dvs_for_context,
                                    {'network_type': type_})

        segment = {'network_type': constants.TYPE_VLAN,
                   'physical_network': 'wrong_network'}
        self.assertRaisesRegexp(exceptions.NoDVSForPhysicalNetwork,
                                "No dvs mapped for physical network: %s" %
                                segment['physical_network'],
                                self.agent._lookup_dvs_for_context,
                                segment)

        segment = {'network_type': constants.TYPE_VLAN,
                   'physical_network': 'physnet1'}
        try:
            self.agent._lookup_dvs_for_context(segment)
        except Exception:
            self.fail('_lookup_dvs_for_context() function should not throw any'
                      ' exceptions with correct segment data: %s' % segment)

    @mock.patch('mech_vmware_dvs.agentDVS.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_update_port_postcommit_uncontrolled_dvs(self, is_valid_dvs):
        is_valid_dvs.side_effect = exceptions.NoDVSForPhysicalNetwork(
            physical_network='_dummy_physical_net_')
        self.port_context.current['admin_state_up'] = True
        self.port_context.original['admin_state_up'] = False

        self.assertRaises(exceptions.InvalidSystemState,
                          self.agent.update_port_postcommit,
                          self.port_context.current,
                          self.port_context.original,
                          self.port_context.network.network_segments[0],
                          self.sg_info)
        self.assertTrue(is_valid_dvs.called)
        self.assertFalse(self.dvs.switch_port_blocked_state.called)

    @mock.patch('mech_vmware_dvs.agentDVS.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_update_port_postcommit(self, is_valid_dvs):
        is_valid_dvs.return_value = self.dvs
        self.port_context.current['admin_state_up'] = True
        self.port_context.original['admin_state_up'] = False
        self.agent.update_port_postcommit(
            self.port_context.current,
            self.port_context.original,
            self.port_context.network.network_segments[0],
            self.sg_info
        )
        self.assertTrue(is_valid_dvs.called)
        self.assertTrue(self.dvs.switch_port_blocked_state.called)

    @mock.patch('mech_vmware_dvs.agentDVS.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_delete_port_postcommit_uncontrolled_dvs(self, is_valid_dvs):
        is_valid_dvs.side_effect = exceptions.NoDVSForPhysicalNetwork(
            physical_network='_dummy_physical_net_')

        self.assertRaises(exceptions.InvalidSystemState,
                          self.agent.delete_port_postcommit,
                          self.port_context.current,
                          self.port_context.original,
                          self.port_context.network.network_segments[0],
                          self.sg_info)
        self.assertTrue(is_valid_dvs.called)
        self.assertFalse(self.dvs.release_port.called)

    @mock.patch('mech_vmware_dvs.agentDVS.dvs_neutron_agent.DVSAgent.'
                '_lookup_dvs_for_context')
    def test_delete_port_postcommit(self, is_valid_dvs):
        is_valid_dvs.return_value = self.dvs

        self.agent.delete_port_postcommit(
            self.port_context.current,
            self.port_context.original,
            self.port_context.network.network_segments[0],
            self.sg_info
        )
        self.assertTrue(is_valid_dvs.called)
        self.assertTrue(self.dvs.release_port.called)

    def test_update_security_groups_no_update_when_sg_didnt_change(self):
        self.agent._update_security_groups(self.dvs, self.port_context.current,
                                           self.port_context.original,
                                           self.sg_info, False)
        self.assertFalse(self.dvs.update_port_rules.called)

    def test_update_security_groups_update_when_sg_added(self):
        context, sg_info = self._create_port_context(
            current=self._create_port_dict(
                security_groups=[FAKE_SECURITY_GROUPS.NEW]),
        )
        self.agent._update_security_groups(self.dvs, context.current,
                                           context.original, sg_info,
                                           False)
        self.dvs.update_port_rules.assert_called_once_with([context.current])

    def test_update_security_groups_update_when_sg_removed(self):
        context, sg_info = self._create_port_context(
            original=self._create_port_dict(
                security_groups=[FAKE_SECURITY_GROUPS.REMOVED])
        )
        self.agent._update_security_groups(self.dvs, context.current,
                                           context.original, sg_info, False)
        self.dvs.update_port_rules.assert_called_once_with([context.current])

    def test_update_security_groups_force_flag(self):
        self.port_context.current['security_groups'] = []
        self.agent._update_security_groups(self.dvs, self.port_context.current,
                                           self.port_context.original,
                                           self.sg_info, True)
        self.dvs.update_port_rules.assert_called_once_with(
            [self.port_context.current])

    def test_update_security_groups_containing_remote_group_id(self):
        current = self._create_port_dict(
            security_groups=[FAKE_SECURITY_GROUPS.NEW])
        security_groups = {
            FAKE_SECURITY_GROUPS.NEW: [{'remote_group_id': 'other',
                                        'ethertype': 'IPv4'},
                                       {'other': 'rule'}]
        }
        ips = ['192.168.0.1', '192.168.0.2']
        sg_member_ips = {'other': {'IPv4': ips}}
        context, sg_info = self._create_port_context(
            current=current,
            security_groups=security_groups,
            sg_member_ips=sg_member_ips
        )
        self.agent._update_security_groups(self.dvs, context.current,
                                           context.original, sg_info, True)
        self.dvs.update_port_rules.assert_called_once_with([context.current])
        self.assertEqual(CONSTANT_SG_RULE,
                         context.current['security_group_rules'][0])
        self.assertEqual(ips,
                         context.current['security_group_rules'][1]['ip_set'])

    def test_update_security_groups_updates_only_dvs_ports(self):
        p1, p2, p3, p4 = ports = self._create_ports()
        security_groups = {
            FAKE_SECURITY_GROUPS.CONSTANT: [
                {'remote_group_id': FAKE_SECURITY_GROUPS.CONSTANT,
                 'ethertype': 'IPv4'},
                {'other': 'rule'}]}
        ips = ['192.168.0.1', '192.168.0.2']
        sg_member_ips = {FAKE_SECURITY_GROUPS.CONSTANT: {'IPv4': ips}}
        context, sg_info = self._create_port_context(
            security_groups=security_groups,
            ports=ports,
            sg_member_ips=sg_member_ips)
        self.agent._update_security_groups(self.dvs, context.current,
                                           context.original, sg_info, True)
        self.assertTrue(self.dvs.update_port_rules.called)
        updated_ports = self.dvs.update_port_rules.call_args[0][0]
        self.assertListEqual(sorted([context.current, p1, p3, p4]),
                             sorted(updated_ports))

    def test_update_security_groups_sg_is_others_remote_group_id(self):
        p1, p2, p3, p4 = ports = self._create_ports()
        current = self._create_port_dict(
            security_groups=[FAKE_SECURITY_GROUPS.NEW,
                             FAKE_SECURITY_GROUPS.CONSTANT])
        security_groups = {
            'other': [{'remote_group_id': FAKE_SECURITY_GROUPS.NEW,
                       'ethertype': 'IPv4'},
                      {'other': 'rule'}],
            FAKE_SECURITY_GROUPS.CONSTANT: [
                {'remote_group_id': FAKE_SECURITY_GROUPS.CONSTANT,
                 'ethertype': 'IPv4'},
                {'other': 'rule'}]
        }
        ips = ['192.168.0.1', '192.168.0.2']
        sg_member_ips = {FAKE_SECURITY_GROUPS.NEW: {'IPv4': ips},
                         FAKE_SECURITY_GROUPS.CONSTANT: {
                             'IPv4': ['192.168.2.10']}}
        context, sg_info = self._create_port_context(
            current=current,
            ports=ports,
            security_groups=security_groups,
            sg_member_ips=sg_member_ips)
        self.agent._update_security_groups(self.dvs, context.current,
                                           context.original, sg_info, False)
        self.assertTrue(self.dvs.update_port_rules.called)
        updated_ports = self.dvs.update_port_rules.call_args[0][0]
        self.assertListEqual(sorted([context.current, p4]),
                             sorted(updated_ports))
        self.assertEqual(ips,
                         p4['security_group_rules'][1]['ip_set'])
        self.assertEqual(1, len(p3['security_group_rules']))

    def test_update_security_groups_sg_with_no_rules(self):
        self.port_context.current['security_groups'].append(
            FAKE_SECURITY_GROUPS.NEW)
        self.agent._update_security_groups(self.dvs, self.port_context.current,
                                           self.port_context.original,
                                           self.sg_info, True)
        self.dvs.update_port_rules.assert_called_once_with(
            [self.port_context.current])
        sg_rules = self.port_context.current['security_group_rules']
        self.assertEqual(1, len(sg_rules))
        self.assertEqual(CONSTANT_SG_RULE, sg_rules[0])

    def test_update_security_groups_FAKE_PORT_ID(self):
        self.port_context.current['id'] = endpoints.FAKE_PORT_ID
        self.agent._update_security_groups(self.dvs, self.port_context.current,
                                           self.port_context.original,
                                           self.sg_info, True)
        self.assertTrue(self.dvs.update_port_rules.called)

    def test_update_security_groups_update_of_sg_without_ports(self):
        current = self._create_port_dict(vif_type='fake')
        current.update({
            'id': endpoints.FAKE_PORT_ID,
            'security_groups': ['sg_without_ports']
        })
        self.agent._update_security_groups(self.dvs, current,
                                           self.port_context.original,
                                           self.sg_info, True)
        self.assertFalse(self.dvs.update_port_rules.called)

    def _create_ports(self, security_groups=None):
        ports = [
            self._create_port_dict(),
            self._create_port_dict(vif_type='ovs',
                                   vif_details={'other': 'details'},
                                   security_groups=security_groups),
            self._create_port_dict(security_groups=security_groups),
            self._create_port_dict(security_groups=['other'])
        ]
        return ports

    def _create_port_context(self, current=None, original=None, ports=None,
                             security_groups=None, sg_member_ips=None):
        current = current or self._create_port_dict()
        original = original or self._create_port_dict()
        original['id'] = current['id']
        ports = ports or self._create_ports(
            security_groups=current['security_groups'])
        ports.append(current)
        context = mock.Mock(
            current=current,
            original=original,
            network=self._create_network_context())

        devices = {p['id']: p for p in ports}
        devices[current['id']] = current
        security_groups = security_groups or {}
        for p in ports:
            for sg in p['security_groups']:
                if sg not in security_groups:
                    security_groups[sg] = []

        sg_info = {
            'devices': devices,
            'security_groups': security_groups,
            'sg_member_ips': sg_member_ips or {},
        }
        return context, sg_info

    def _create_port_dict(self, security_groups=None, vif_type=None,
                          vif_details=None):
        security_groups = security_groups or []
        security_groups = list(security_groups)
        security_groups.append(FAKE_SECURITY_GROUPS.CONSTANT)
        return {
            'id': '_dummy_port_id_%s' % id({}),
            'admin_state_up': True,
            'security_groups': security_groups,
            'binding:host_id': '_id_server_',
            'binding:vif_type': vif_type or util.DVS,
            'status': 'DOWN',
            'security_group_rules': [CONSTANT_SG_RULE],
            'binding:vif_details': vif_details or {
                'dvs_port_key': '_dummy_dvs_port_key_'}}

    def _create_network_context(self, network_type='vlan'):
        return mock.Mock(current={'id': '_dummy_net_id_'},
                         network_segments=[{'id': '_id_segment_',
                                            'network_type': network_type,
                                            'physical_network': 'physnet1'}])
