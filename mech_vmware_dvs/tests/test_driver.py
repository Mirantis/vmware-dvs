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
#

import mock
from neutron.plugins.common import constants
from neutron.tests import base

from mech_vmware_dvs import config
from mech_vmware_dvs import endpoints
from mech_vmware_dvs import driver
from mech_vmware_dvs import exceptions

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


class VMwareDVSMechanismDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(VMwareDVSMechanismDriverTestCase, self).setUp()
        self.driver = driver.VMwareDVSMechanismDriver()
        self.driver._bound_ports = set()
        self.dvs = mock.Mock()
        self.dvs_notifier = mock.Mock()
        self.driver.network_map = {'physnet1': self.dvs}

    @mock.patch('neutron.db.api.get_session')
    @mock.patch('mech_vmware_dvs.util.create_network_map_from_config',
                return_value='network_map')
    def test_initialize(self, create_network_map_from_config, get_session):
        self.driver.initialize()
        create_network_map_from_config.assert_called_once_with(
            config.CONF.ml2_vmware)
        self.assertEqual('network_map', self.driver.network_map)

    def test_create_network_precommit(self):
        context = self._create_network_context()
        self.driver.create_network_precommit(context)
        self.dvs_notifier.create_network_cast.assert_called_once_with(
                          context.current, context.network_segments[0])

    def test_create_network_precommit_dont_support_other_network_type(self):
        for type_ in NOT_SUPPORTED_TYPES:
            context = self._create_network_context(type_)
            self.driver.create_network_precommit(context)
            self.assertFalse(self.dvs.create_network.called)

    def test_create_network_precommit_when_network_not_mapped(self):
        context = self._create_network_context()
        self.driver.network_map = {}
        try:
            self.driver.create_network_precommit(context)
        except Exception:
            self.fail('Should not throw any exceptions')

    def test_update_network_precommit(self):
        context = self._create_network_context()
        self.driver.update_network_precommit(context)
        self.dvs_notifier.update_network_cast.assert_called_once_with(
                          context.current, context.original)

    def test_update_network_precommit_when_network_not_mapped(self):
        context = self._create_network_context()
        self.driver.network_map = {}
        try:
            self.driver.update_network_precommit(context)
        except Exception:
            self.fail('Should not throw any exceptions')

    def test_update_network_precommit_dont_support_other_network_type(self):
        for type_ in NOT_SUPPORTED_TYPES:
            context = self._create_network_context(type_)
            self.driver.update_network_precommit(context)
            self.assertFalse(self.dvs.create_network.called)

    def test_delete_network_postcommit(self):
        context = self._create_network_context()
        self.driver.delete_network_postcommit(context)
        self.dvs.delete_network.assert_called_once_with(context.current)

    def test_delete_network_postcommit_dont_support_other_network_type(self):
        for type_ in NOT_SUPPORTED_TYPES:
            context = self._create_network_context(type_)
            self.driver.delete_network_postcommit(context)
            self.assertFalse(self.dvs.create_network.called)

    def test_delete_network_postcommit_when_network_is_not_mapped(self):
        context = self._create_network_context()
        self.driver.network_map = {}
        try:
            self.driver.delete_network_postcommit(context)
        except Exception:
            self.fail('Should not throw any exceptions')

    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._update_security_groups')
    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test_update_port_postcommit(self, hypervisor_by_host,
                                    _update_security_groups):
        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)
        port_context = self._create_port_context()

        self.driver.update_port_postcommit(port_context)

        self.assertTrue(_update_security_groups.called)

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._lookup_dvs_for_context')
    def test_update_port_postcommit_uncontrolled_dvs(
            self, is_valid_dvs, hypervisor_by_host):
        is_valid_dvs.side_effect = exceptions.NoDVSForPhysicalNetwork(
            physical_network='_dummy_physical_net_')

        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)

        self.assertRaises(
            exceptions.InvalidSystemState, self.driver.update_port_postcommit,
            self._create_port_context())
        self.assertTrue(is_valid_dvs.called)
        self.assertFalse(self.dvs.switch_port_blocked_state.called)

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test__port_belongs_to_vmware__unbinded_port(self, get_hypervisor):
        context = self._create_port_context()
        port = context.curren
        port.pop('binding:host_id')

        func = mock.Mock(__name__='dummy_name')
        decorated = driver.port_belongs_to_vmware(func)
        self.assertFalse(decorated(None, context))
        self.assertFalse(func.called)

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test__port_belongs_to_vmware__invalid_hypervisor(
            self, get_hypervisor):
        context = self._create_port_context()
        get_hypervisor.return_value = mock.Mock(
            hypervisor_type=INVALID_HYPERVISOR_TYPE)

        func = mock.Mock(__name__='dummy_name')
        decorated = driver.port_belongs_to_vmware(func)
        self.assertFalse(decorated(None, context))
        self.assertFalse(func.called)

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test__port_belongs_to_vmware__not_found(self, get_hypervisor):
        get_hypervisor.side_effect = exceptions.HypervisorNotFound
        context = self._create_port_context()

        func = mock.Mock(__name__='dummy_name', return_value=True)
        decorated = driver.port_belongs_to_vmware(func)
        self.assertFalse(decorated(None, context))
        self.assertFalse(func.called)
        self.assertTrue(get_hypervisor.called)

    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._update_security_groups')
    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test_delete_port_postcommit_when_KeyError(self, *args):
        context = self._create_port_context()
        self.driver._bound_ports = {1, 2}
        self.driver.delete_port_postcommit(context)
        self.assertEqual({1, 2}, self.driver._bound_ports)

    def test_update_security_groups_no_update_when_sg_didnt_change(self):
        context = self._create_port_context()
        self.driver._update_security_groups(self.dvs, context, False)

        self.assertFalse(self.dvs.update_port_rules.called)
        self.assertFalse(context._plugin.get_ports.called)
        self.assertFalse(context._plugin.security_group_info_for_ports.called)

    def test_update_security_groups_update_when_sg_added(self):
        context = self._create_port_context(
            current=self._create_port_dict(security_groups=[
                FAKE_SECURITY_GROUPS.NEW]),
        )
        self.driver._update_security_groups(self.dvs, context, False)
        self.dvs.update_port_rules.assert_called_once_with([context.current])

    def test_update_security_groups_update_when_sg_removed(self):
        context = self._create_port_context(
            original=self._create_port_dict(security_groups=[
                FAKE_SECURITY_GROUPS.REMOVED
            ])
        )
        self.driver._update_security_groups(self.dvs, context, False)
        self.dvs.update_port_rules.assert_called_once_with([context.current])

    def test_update_security_groups_force_flag(self):
        context = self._create_port_context()
        context.current['security_groups'] = []
        self.driver._update_security_groups(self.dvs, context, True)
        self.dvs.update_port_rules.assert_called_once_with([context.current])

    def test_update_security_groups_when_security_group_rules_absent(self):
        context = self._create_port_context()
        del context.current['security_group_rules']
        self.driver._update_security_groups(self.dvs, context, True)
        self.dvs.update_port_rules.assert_called_once_with([context.current])
        self.assertIn('security_group_rules', context.current)

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
        context = self._create_port_context(current=current,
                                            security_groups=security_groups,
                                            sg_member_ips=sg_member_ips)
        self.driver._update_security_groups(self.dvs, context, True)
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
        context = self._create_port_context(
            security_groups=security_groups,
            ports=ports,
            sg_member_ips=sg_member_ips)
        self.driver._update_security_groups(self.dvs, context, True)
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
        context = self._create_port_context(current=current,
                                            ports=ports,
                                            security_groups=security_groups,
                                            sg_member_ips=sg_member_ips)
        self.driver._update_security_groups(self.dvs, context, False)
        self.assertTrue(self.dvs.update_port_rules.called)
        updated_ports = self.dvs.update_port_rules.call_args[0][0]
        self.assertListEqual(sorted([context.current, p4]),
                             sorted(updated_ports))
        self.assertEqual(ips,
                         p4['security_group_rules'][1]['ip_set'])
        self.assertEqual(1, len(p3['security_group_rules']))

    def test_update_security_groups_sg_with_no_rules(self):
        context = self._create_port_context()
        context.current['security_groups'].append(FAKE_SECURITY_GROUPS.NEW)
        self.driver._update_security_groups(self.dvs, context, True)
        self.dvs.update_port_rules.assert_called_once_with(
            [context.current])
        sg_rules = context.current['security_group_rules']
        self.assertEqual(1, len(sg_rules))
        self.assertEqual(CONSTANT_SG_RULE, sg_rules[0])

    def test_update_security_groups_FAKE_PORT_ID(self):
        context = self._create_port_context()
        context.current['id'] = endpoints.FAKE_PORT_ID
        self.driver._update_security_groups(self.dvs, context, True)
        self.assertTrue(self.dvs.update_port_rules.called)

    def test_update_security_groups_update_of_sg_without_ports(self):
        current = self._create_port_dict(vif_type='fake')
        context = self._create_port_context(current=current)
        context.current['id'] = endpoints.FAKE_PORT_ID
        context.current['security_groups'] = ['sg_without_ports']

        self.driver._update_security_groups(self.dvs, context, True)
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
        context._plugin.get_ports.return_value = ports
        devices = {p['id']: p for p in ports}
        devices[current['id']] = current
        security_groups = security_groups or {}
        for p in ports:
            for sg in p['security_groups']:
                if sg not in security_groups:
                    security_groups[sg] = []

        context._plugin.security_group_info_for_ports.return_value = {
            'devices': devices,
            'security_groups': security_groups,
            'sg_member_ips': sg_member_ips or {},
        }
        return context

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
            'binding:vif_type': vif_type or self.driver.vif_type,
            'status': 'DOWN',
            'security_group_rules': [CONSTANT_SG_RULE],
            'binding:vif_details': vif_details or {
                'dvs_port_key': '_dummy_dvs_port_key_'}}

    def _create_network_context(self, network_type='vlan'):
        return mock.Mock(current={'id': '_dummy_net_id_'},
                         network_segments=[
                             {'id': '_id_segment_',
                              'network_type': network_type,
                              'physical_network': 'physnet1'}])
