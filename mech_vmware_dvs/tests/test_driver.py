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
from neutron.context import Context

from mech_vmware_dvs import config
from mech_vmware_dvs import driver
from mech_vmware_dvs import exceptions

NOT_SUPPORTED_TYPES = [
    constants.TYPE_FLAT,
    constants.TYPE_GRE,
    constants.TYPE_LOCAL,
    constants.TYPE_VXLAN,
    constants.TYPE_NONE
]
VALID_HYPERVISOR_TYPE = 'VMware vCenter Server'
INVALID_HYPERVISOR_TYPE = '_invalid_hypervisor_'

fake_endpoint_context = {
    u'auth_token': u'da91541654c64e3ca416ce7d0c2bfbcf',
    u'domain': None,
    u'is_admin': True,
    u'project_domain': None,
    u'project_id': u'0258e176b3be4a14949ee19f9c439a82',
    u'project_name': u'admin',
    u'read_deleted': u'no',
    u'read_only': False,
    u'request_id': u'req-49edb29f-7753-49c9-a64d-e5232f05e76a',
    u'resource_uuid': None,
    u'roles': [u'admin'],
    u'show_deleted': False,
    u'tenant': u'0258e176b3be4a14949ee19f9c439a82',
    u'tenant_id': u'0258e176b3be4a14949ee19f9c439a82',
    u'tenant_name': u'admin',
    u'timestamp': u'2015-06-08 13:23:37.601222',
    u'user': u'91d0aa5ef1b447de90956bc1c60d0404',
    u'user_domain': None,
    u'user_id': u'91d0aa5ef1b447de90956bc1c60d0404',
    u'user_identity': u'91d0aa5ef1b447de90956bc1c60d0404'
                      u' 0258e176b3be4a14949ee19f9c439a82 - - -',
    u'user_name': u'admin'}


class FAKE_SECURITY_GROUPS(object):
    NEW = 'new_sg'
    CONSTANT = 'constant_sg'
    REMOVED = 'removed_sg'


CONSTANT_SG_RULE = {'constant rule': 'some_rule'}


class EndPointBaseTestCase(base.BaseTestCase):
    def setUp(self):
        class ConcreteEndPoint(driver.EndPointBase):
            def info(self, ctxt, publisher_id, event_type, payload, metadata):
                pass

        super(EndPointBaseTestCase, self).setUp()
        self.dvs = mock.Mock(name='dvs')
        self.driver = mock.Mock()
        self.driver.network_map = {'physnet1': self.dvs,
                                   'physnet2': mock.Mock(name='dvs2')}
        patch = mock.patch('neutron.manager.NeutronManager.get_plugin')
        self.plugin = patch.start()
        self.addCleanup(patch.stop)

        self.endpoint = ConcreteEndPoint(self.driver)

    def test_update_security_group(self):
        def PortContext(plugin, plugin_context, port, network, binding,
                        binding_levels, original_port=None):
            expected = Context.from_dict(fake_endpoint_context)
            self.assertEqual(Context.to_dict(expected),
                             Context.to_dict(plugin_context))
            self.assertIs(self.plugin.return_value, plugin)
            self.assertDictEqual(network, {'id': 'fake'})
            self.assertDictEqual(
                port, {'id': driver.FAKE_PORT_ID,
                       'security_groups': ['_dummy_security_group_id_']})
            self.assertIsNone(binding)
            self.assertIsNone(binding_levels)
            self.assertIsNone(original_port)
            return '_port_context_'

        with mock.patch('neutron.plugins.ml2.driver_context.PortContext',
                        new=PortContext):
            self.endpoint.update_security_group(fake_endpoint_context,
                                                '_dummy_security_group_id_')

        for key, dvs in self.driver.network_map.iteritems():
            self.driver._update_security_groups.assert_any_call(
                dvs, '_port_context_', force=True)


class SecurityGroupRuleCreateEndPointTestCase(base.BaseTestCase):
    def setUp(self):
        super(SecurityGroupRuleCreateEndPointTestCase, self).setUp()
        self.payload = {
            'security_group_rule': {
                'security_group_id': '_dummy_security_group_id_'}}
        self.driver = mock.Mock()
        self.endpoint = driver.SecurityGroupRuleCreateEndPoint(self.driver)

    @mock.patch('mech_vmware_dvs.driver.SecurityGroupRuleCreateEndPoint'
                '.update_security_group')
    def test_info(self, update_security_group):
        self.endpoint.info(fake_endpoint_context, '_publisher_id_',
                           '_event_type_', self.payload, '_metadata_')
        update_security_group.assert_called_once_with(
            fake_endpoint_context,
            '_dummy_security_group_id_')


class SecurityGroupRuleDeleteEndPointTestCase(base.BaseTestCase):
    def setUp(self):
        super(SecurityGroupRuleDeleteEndPointTestCase, self).setUp()
        self.payload = {
            'security_group_rule_id': '_security_group_rule_id_'}
        self.driver = mock.Mock()
        self.endpoint = driver.SecurityGroupRuleDeleteEndPoint(self.driver)

    @mock.patch('mech_vmware_dvs.driver.SecurityGroupRuleDeleteEndPoint'
                '.get_security_group_for',
                return_value='_dummy_security_group_id_')
    def test_info_when_delete_start(self, get_security_group_for):
        self.endpoint.sgr_to_sg[
            '_security_group_rule_id_'] = '_dummy_security_group_id_'
        self.endpoint.info(fake_endpoint_context, '_publisher_id_',
                           '_event_type_.start', self.payload, '_metadata_')
        get_security_group_for.assert_called_once_with(
            fake_endpoint_context,
            '_security_group_rule_id_')
        self.assertEqual({
            '_security_group_rule_id_': '_dummy_security_group_id_'},
            self.endpoint.sgr_to_sg)

    @mock.patch('mech_vmware_dvs.driver.SecurityGroupRuleDeleteEndPoint'
                '.update_security_group')
    def test_info_when_delete_end(self, update_security_group):
        self.endpoint.sgr_to_sg[
            '_security_group_rule_id_'] = '_dummy_security_group_id_'
        self.endpoint.info(fake_endpoint_context, '_publisher_id_',
                           '_event_type_.end', self.payload, '_metadata_')
        update_security_group.assert_called_once_with(
            fake_endpoint_context,
            '_dummy_security_group_id_')
        self.assertEqual({}, self.endpoint.sgr_to_sg)

    @mock.patch('neutron.manager.NeutronManager.get_plugin')
    def test_get_security_group_for(self, get_plugin):
        get_plugin.return_value.get_security_group_rule.return_value = {
            'security_group_id': 'some_id'}
        result = self.endpoint.get_security_group_for(
            fake_endpoint_context,
            '_dummy_security_rule_id_')
        self.assertEqual('some_id', result)


class VMwareDVSMechanismDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(VMwareDVSMechanismDriverTestCase, self).setUp()
        self.driver = driver.VMwareDVSMechanismDriver()
        self.driver._bound_ports = set()
        self.dvs = mock.Mock()
        self.driver.network_map = {'physnet1': self.dvs}

    @mock.patch('mech_vmware_dvs.util.create_network_map_from_config',
                return_value='network_map')
    def test_initialize(self, m):
        self.driver.initialize()
        m.assert_called_once_with(config.CONF.ml2_vmware)
        self.assertEqual('network_map', self.driver.network_map)

    def test_create_network_precommit(self):
        context = self._create_network_context()
        self.driver.create_network_precommit(context)
        self.dvs.create_network.assert_called_once_with(
            context.current,
            context.network_segments[0])

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
        self.dvs.update_network.assert_called_once_with(context.current)

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
    def test_update_port_postcommit(self,
                                    _update_security_groups):
        port_context = self._create_port_context()

        self.driver.update_port_postcommit(port_context)
        self.assertEqual(
            self.dvs.switch_port_blocked_state.call_args_list,
            [mock.call(port_context.current)])
        self.assertTrue(_update_security_groups.called)

    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._port_belongs_to_vmware')
    def test_update_port_postcommit_invalid_port(self, is_valid_port):
        is_valid_port.return_value = False

        self.driver.update_port_postcommit(self._create_port_context())

        self.assertTrue(is_valid_port.called)
        self.assertFalse(self.dvs.switch_port_blocked_state.called)

    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._port_belongs_to_vmware')
    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._lookup_dvs_for_context')
    def test_update_port_postcommit_uncontrolled_dvs(
            self, is_valid_dvs, is_valid_port):
        is_valid_dvs.side_effect = exceptions.NoDVSForPhysicalNetwork(
            physical_network='_dummy_physical_net_')
        is_valid_port.return_value = True

        self.assertRaises(
            exceptions.InvalidSystemState, self.driver.update_port_postcommit,
            self._create_port_context())
        self.assertTrue(is_valid_dvs.called)
        self.assertFalse(self.dvs.switch_port_blocked_state.called)

    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._get_bound_ports', return_value=set())
    def test_bind_port(self, _getbound_ports):
        context = self._create_port_context()

        self.dvs.get_unbound_port_key.return_value = '_unbound_key_'


        self.driver.bind_port(context)

        self.assertEqual(
            context.set_binding.call_count,
            len(context.network.network_segments))
        for idx, segment in enumerate(context.network.network_segments):
            vif_details = dict(self.driver.vif_details)
            vif_details['dvs_port_key'] = '_unbound_key_'
            self.assertEqual(
                context.set_binding.call_args_list[idx],
                mock.call(
                    segment['id'],
                    self.driver.vif_type, vif_details,
                    status='ACTIVE'))

    def test__getbound_ports(self):
        context = self._create_port_context()
        good_port = {'binding:vif_details': {
            'dvs_port_key': '_dummy_dvs_port_key_'}}
        wrong_port1 = {}
        wrong_port2 = {'binding:vif_details': {}}
        context._plugin.get_ports.return_value = [good_port, wrong_port1,
                                                  wrong_port2]
        bound_ports = {1, 2, 3}
        self.driver._bound_ports = bound_ports

        result = self.driver._get_bound_ports(context)

        self.assertEqual(bound_ports.union({'_dummy_dvs_port_key_'}), result)

    def test_delete_port_postcommit(self):
        context = self._create_port_context()
        self.driver._bound_ports = {1, 2, '_dummy_dvs_port_key_'}
        self.driver.delete_port_postcommit(context)
        self.assertEqual({1, 2}, self.driver._bound_ports)

    def test_delete_port_postcommit_when_KeyError(self):
        context = self._create_port_context()
        self.driver._bound_ports = {1, 2}
        self.driver.delete_port_postcommit(context)
        self.assertEqual({1, 2}, self.driver._bound_ports)

    def test__update_admin_state_up(self):
        context = self._create_port_context()
        self.driver._update_admin_state_up(self.dvs, context, False)
        self.assertFalse(self.dvs.switch_port_blocked_state.called)

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
        context.current['id'] = driver.FAKE_PORT_ID
        self.driver._update_security_groups(self.dvs, context, True)
        self.assertTrue(self.dvs.update_port_rules.called)

    def test_update_security_groups_update_of_sg_without_ports(self):
        current = self._create_port_dict(vif_type='fake')
        context = self._create_port_context(current=current)
        context.current['id'] = driver.FAKE_PORT_ID
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
