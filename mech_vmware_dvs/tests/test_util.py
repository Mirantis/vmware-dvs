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

import mock
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util
from neutron.tests import base

from mech_vmware_dvs import config
from mech_vmware_dvs import exceptions
from mech_vmware_dvs import util


CONF = config.CONF

fake_network = {'id': '34e33a31-516a-439f-a186-96ac85155a8c',
                'name': '_fake_network_',
                'admin_state_up': True}
fake_segment = {'segmentation_id': '102'}
fake_port = {
    'id': '_dummy_port_id_',
    'admin_state_up': True,
    'device_id': '_dummy_server_id_',
    'security_group_rules': [{'ethertype': 'IPv4',
                              'direction': 'ingress'}]
}

fake_security_group = {'description': u'Default security group',
                       'id': u'9961d207-c96c-4907-be9e-d979d5353885',
                       'name': u'default',
                       'security_group_rules': [
                           {'direction': u'ingress',
                            'ethertype': u'IPv4',
                            'id': u'0e78cacc-ef5c-45ac-8a11-f9ce9138dce5',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': u'9961d207-c96c-4907-'
                                               u'be9e-d979d5353885',
                            'remote_ip_prefix': None,
                            'security_group_id': u'9961d207-c96c-4907-be9e-'
                                                 u'd979d5353885',
                            'tenant_id': u'9d2c4b37b9474bcbbddacc5f03fb89c4'},
                           {'direction': u'ingress',
                            'ethertype': u'IPv6',
                            'id': u'35e8a8e2-8410-4fae-ad21-26dd3f403b92',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': u'9961d207-c96c-4907'
                                               u'-be9e-d979d5353885',
                            'remote_ip_prefix': None,
                            'security_group_id': u'9961d207-c96c-'
                                                 u'4907-be9e-d979d5353885',
                            'tenant_id': u'9d2c4b37b9474bcbbddacc5f03fb89c4'},
                           {'direction': u'egress',
                            'ethertype': u'IPv6',
                            'id': u'52a93b8c-25aa-4829-9a6b-0b7ec3f7f89c',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': None,
                            'remote_ip_prefix': None,
                            'security_group_id': u'9961d207-c96c-4907-'
                                                 u'be9e-d979d5353885',
                            'tenant_id': u'9d2c4b37b9474bcbbddacc5f03fb89c4'},
                           {'direction': u'ingress',
                            'ethertype': u'IPv4',
                            'id': u'625b0755-30e0-4ff6-b3e4-d0f21c5c09e2',
                            'port_range_max': 22L,
                            'port_range_min': 22L,
                            'protocol': u'tcp',
                            'remote_group_id': None,
                            'remote_ip_prefix': u'0.0.0.0/0',
                            'security_group_id': u'9961d207-c96c-4907-'
                                                 u'be9e-d979d5353885',
                            'tenant_id': u'9d2c4b37b9474bcbbddacc5f03fb89c4'},
                           {'direction': u'egress',
                            'ethertype': u'IPv4',
                            'id': u'bd00ea5d-91ea-4a39-80ca-45ce73a3bc6f',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': None,
                            'remote_group_id': None,
                            'remote_ip_prefix': None,
                            'security_group_id': u'9961d207-c96c-4907-'
                                                 u'be9e-d979d5353885',
                            'tenant_id': u'9d2c4b37b9474bcbbddacc5f03fb89c4'},
                           {'direction': u'ingress',
                            'ethertype': u'IPv4',
                            'id': u'c7c11328-a8ae-42a3-b30e-9cd2ac1cbef5',
                            'port_range_max': None,
                            'port_range_min': None,
                            'protocol': u'icmp',
                            'remote_group_id': None,
                            'remote_ip_prefix': u'0.0.0.0/0',
                            'security_group_id': u'9961d207-c96c-4907-'
                                                 u'be9e-d979d5353885',
                            'tenant_id': u'9d2c4b37b9474bcbbddacc5f03fb89c4'}],
                       'tenant_id': u'9d2c4b37b9474bcbbddacc5f03fb89c4'}


class UtilBaseTestCase(base.BaseTestCase):

    def _get_factory_mock(self, expected_names):
        def create_side_effect(namespace):
            if namespace in expected_names:
                return mock.Mock(name=namespace)
            else:
                self.fail('Unexpected call. Namespace: %s' % namespace)

        factory = mock.Mock()
        factory.create.side_effect = create_side_effect
        return factory


class DVSControllerBaseTestCase(UtilBaseTestCase):
    """Base of all DVSController tests"""

    def setUp(self):
        super(DVSControllerBaseTestCase, self).setUp()
        self.dvs_name = 'dvs_name'
        self.vim = mock.Mock()
        self.connection = self._get_connection_mock(self.dvs_name)

        self.datacenter = 'datacenter1'
        #self.use_patch('mech_vmware_dvs.util.DVSController._get_datacenter',
        #               return_value=self.datacenter)
        self.dvs = mock.Mock()
        dvs_param = [self.dvs, self.datacenter]
        self.use_patch('mech_vmware_dvs.util.DVSController._get_dvs',
                       return_value=dvs_param)
        self.dvs = dvs_param[0]
        self.datacenter = dvs_param[1]

        self.controller = util.DVSController(self.dvs_name, self.connection)

    def use_patch(self, *args, **kwargs):
        patch = mock.patch(*args, **kwargs)
        self.addCleanup(patch.stop)
        return patch.start()

    def _get_connection_mock(self, dvs_name):
        raise NotImplementedError


class DVSControllerTestCase(DVSControllerBaseTestCase):
    """Tests of DVSController that don't call API methods"""

    def test_creation(self):
        self.assertEqual(self.datacenter, self.controller._datacenter)
        self.assertEqual(self.dvs, self.controller._dvs)
        self.assertIs(self.connection, self.controller.connection)

    def test__get_net_name(self):
        expect = self.dvs_name + fake_network['id']
        self.assertEqual(expect, self.controller._get_net_name(self.dvs_name,
                                                               fake_network))

    def _get_connection_mock(self, dvs_name):
        return mock.Mock(vim=self.vim)

    class VirtualE1000(object):

        def __init__(self, port_key, switch_uuid):
            self.backing = mock.Mock()
            self.backing.port.portKey = port_key
            self.backing.port.switchUuid = switch_uuid


class DVSControllerNetworkCreationTestCase(DVSControllerBaseTestCase):

    def test_create_network(self):
        try:
            self.controller.create_network(fake_network, fake_segment)
        except AssertionError:
            raise
        except Exception as e:
            self.fail("Can't create network. Reason: %s" % e)
        else:
            self.assertEqual(1, self.connection.invoke_api.call_count)
            self.assertEqual(1, self.connection.wait_for_task.call_count)

    def test_create_network_which_is_blocked(self):
        org_side_effect = self.connection.invoke_api.side_effect

        def side_effect(module, method, *args, **kwargs):
            if method == 'CreateDVPortgroup_Task':
                blocked_spec = kwargs['spec'].defaultPortConfig.blocked
                self.assertEqual('0', blocked_spec.inherited)
                self.assertEqual('true', blocked_spec.value)
                return kwargs['spec']
            else:
                return org_side_effect(module, method, *args, **kwargs)

        self.connection.invoke_api.side_effect = side_effect
        network = dict(fake_network)
        network['admin_state_up'] = False
        self.controller.create_network(network, fake_segment)

    def test_create_network_raises_VMWareDVSException(self):
        # first we count calls
        self.controller.create_network(fake_network, fake_segment)
        api_calls = self.connection.invoke_api.call_count

        # then we throw VimException for every api call
        for i in range(api_calls):
            connection = self._get_connection_mock(self.dvs_name)
            org_side_effect = self.connection.invoke_api.side_effect

            def side_effect(*args, **kwargs):
                if connection.invoke_api.call_count == i + 1:
                    msg = ('Failed test with args: %(args)s '
                           'and kwargs: %(kwargs)s' % {'args': args,
                                                       'kwargs': kwargs})
                    raise vmware_exceptions.VimException(msg)
                return org_side_effect(*args, **kwargs)

            connection.invoke_api.side_effect = side_effect
            controller = util.DVSController(self.dvs_name, connection)
            self.assertRaises(exceptions.VMWareDVSException,
                              controller.create_network, fake_network,
                              fake_segment)

    def _get_connection_mock(self, dvs_name):
        vim = self.vim
        vim.client.factory = self._get_factory_mock((
            'ns0:DVPortgroupConfigSpec',
            'ns0:VMwareDVSPortSetting',
            'ns0:VmwareDistributedVirtualSwitchVlanIdSpec',
            'ns0:BoolPolicy',
            'ns0:DVPortgroupConfig',
            'ns0:DVPortgroupPolicy',
            'ns0:DvsTrafficRule',
            'ns0:DvsDropNetworkRuleAction',
            'ns0:DvsIpNetworkRuleQualifier',
            'ns0:DvsFilterPolicy',
            'ns0:DvsTrafficRuleset',
            'ns0:DvsTrafficFilterConfig'))

        def invoke_api_side_effect(module, method, *args, **kwargs):
            if module is vim_util:
                if method == 'get_objects':
                    if args == (vim, 'Datacenter', 100, ['name']):
                        return mock.Mock(objects=[
                            mock.Mock(obj='datacenter1')
                        ])
            elif module == vim:
                if method == 'CreateDVPortgroup_Task':
                    self.assertEqual((self.dvs,), args)
                    self.assert_create_specification(kwargs['spec'])
                    return kwargs['spec']
            self.fail('Unexpected call. Module: %(module)s; '
                      'method: %(method)s; args: %(args)s, '
                      'kwargs: %(kwargs)s' % {'module': module,
                                              'method': method,
                                              'args': args,
                                              'kwargs': kwargs})

        invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        connection = mock.Mock(invoke_api=invoke_api, vim=vim)
        return connection

    def assert_create_specification(self, spec):
        self.assertEqual(
            self.controller._get_net_name(self.dvs_name, fake_network),
            spec.name
        )
        self.assertEqual('earlyBinding', spec.type)
        self.assertEqual('Managed By Neutron', spec.description)
        vlan_spec = spec.defaultPortConfig.vlan
        self.assertEqual(fake_segment['segmentation_id'],
                         vlan_spec.vlanId)
        self.assertEqual('0', vlan_spec.inherited)
        blocked_spec = spec.defaultPortConfig.blocked
        self.assertEqual('1', blocked_spec.inherited)
        self.assertEqual('false', blocked_spec.value)


class DVSControllerNetworkUpdateTestCase(DVSControllerBaseTestCase):

    def test_update_network(self):
        try:
            self.controller.update_network(fake_network)
        except AssertionError:
            raise
        except Exception as e:
            self.fail("Didn't update network. Reason: %s" % e)
        else:
            self.assertEqual(5, self.connection.invoke_api.call_count)
            self.assertEqual(1, self.connection.wait_for_task.call_count)

    def test_update_network_change_admin_state_to_down(self):
        org_side_effect = self.connection.invoke_api.side_effect

        def side_effect(module, method, *args, **kwargs):
            if 'config' in args:
                config = mock.Mock()
                config.defaultPortConfig.blocked.value = False
                return config
            elif method == 'ReconfigureDVPortgroup_Task':
                blocked_spec = kwargs['spec'].defaultPortConfig.blocked
                self.assertEqual('0', blocked_spec.inherited)
                self.assertEqual('true', blocked_spec.value)
                return kwargs['spec']
            else:
                return org_side_effect(module, method, *args, **kwargs)

        self.connection.invoke_api.side_effect = side_effect
        network = dict(fake_network)
        network['admin_state_up'] = False
        self.controller.update_network(network)

    def test_update_network_when_there_is_no_admin_state_transition(self):
        org_side_effect = self.connection.invoke_api.side_effect
        for state in (True, False):
            def side_effect(module, method, *args, **kwargs):
                if 'config' in args:
                    config = mock.Mock()
                    config.defaultPortConfig.blocked.value = state
                    return config
                elif method == 'ReconfigureDVPortgroup_Task':
                    self.fail('Request is not required, because there is no '
                              'transition of admin state')
                else:
                    return org_side_effect(module, method, *args, **kwargs)

            self.connection.invoke_api.side_effect = side_effect
            network = dict(fake_network)
            network['admin_state_up'] = not state
            self.controller.update_network(network)

    def assert_update_specification(self, spec):
        self.assertEqual('config_version', spec.configVersion)
        blocked_spec = spec.defaultPortConfig.blocked
        self.assertEqual('1', blocked_spec.inherited)
        self.assertEqual('false', blocked_spec.value)

    def _get_connection_mock(self, dvs_name):
        vim = self.vim
        vim.client.factory = self._get_factory_mock((
            'ns0:BoolPolicy',
            'ns0:VMwareDVSPortSetting',
            'ns0:DVPortgroupConfigSpec',
            'ns0:DVPortgroupPolicy'
        ))

        wrong_pg = mock.Mock(_type='DistributedVirtualPortgroup',
                             name='wrong_pg')
        pg_to_update = mock.Mock(_type='DistributedVirtualPortgroup',
                                 name='pg_to_update')
        not_pg = mock.Mock(_type='not_pg', name='not_pg')
        objects = [wrong_pg, pg_to_update, not_pg]

        def invoke_api_side_effect(module, method, *args, **kwargs):
            if module is vim_util:
                if method == 'get_objects':
                    if args == (vim, 'Datacenter', 100, ['name']):
                        return mock.Mock(objects=[
                            mock.Mock(obj='datacenter1')])
                elif method == 'get_object_property':
                    if args == (vim, 'datacenter1', 'network'):
                        return mock.Mock(ManagedObjectReference=objects)
                    elif args == (vim, wrong_pg, 'name'):
                        return 'wrong_pg'
                    elif args == (vim, pg_to_update, 'name'):
                        return util.DVSController._get_net_name(self.dvs_name,
                                                                fake_network)
                    elif args == (vim, not_pg, 'name'):
                        self.fail('Called with not pg')
                    elif args == (vim, pg_to_update, 'config'):
                        config = mock.Mock()
                        config.defaultPortConfig.blocked.value = True
                        config.configVersion = 'config_version'
                        return config
            elif module == vim:
                if method == 'ReconfigureDVPortgroup_Task':
                    self.assertEqual((pg_to_update, ), args)
                    self.assert_update_specification(kwargs['spec'])
                    return kwargs['spec']

            self.fail('Unexpected call. Module: %(module)s; '
                      'method: %(method)s; args: %(args)s, '
                      'kwargs: %(kwargs)s' % {'module': module,
                                              'method': method,
                                              'args': args,
                                              'kwargs': kwargs})

        invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        connection = mock.Mock(invoke_api=invoke_api, vim=vim)
        return connection


class DVSControllerNetworkDeletionTestCase(DVSControllerBaseTestCase):

    def test_delete_network(self):
        try:
            self.controller.delete_network(fake_network)
        except AssertionError:
            raise
        except Exception as e:
            self.fail("Didn't delete network. Reason: %s" % e)
        else:
            self.assertEqual(4, self.connection.invoke_api.call_count)
            self.assertEqual(1, self.connection.wait_for_task.call_count)

    def test_delete_network_tries_to_delete_non_existing_port_group(self):
        org_side_effect = self.connection.invoke_api.side_effect
        vim = self.vim

        def side_effect(module, method, *args, **kwargs):
            if args == (vim, 'datacenter1', 'network'):
                return mock.Mock(ManagedObjectReference=[])
            else:
                return org_side_effect(module, method, *args, **kwargs)

        self.connection.invoke_api.side_effect = side_effect
        try:
            self.controller.delete_network(fake_network)
        except exceptions.PortGroupNotFound:
            self.fail('Deletion of non existing network should pass silent')

    def _get_connection_mock(self, dvs_name):
        vim = self.vim
        wrong_pg = mock.Mock(_type='DistributedVirtualPortgroup',
                             name='wrong_pg')
        pg_to_delete = mock.Mock(_type='DistributedVirtualPortgroup',
                                 name='pg_to_delete')
        not_pg = mock.Mock(_type='not_pg', name='not_pg')
        objects = [wrong_pg, pg_to_delete, not_pg]

        def invoke_api_side_effect(module, method, *args, **kwargs):
            if module is vim_util:
                if method == 'get_objects':
                    if args == (vim, 'Datacenter', 100, ['name']):
                        return mock.Mock(objects=[
                            mock.Mock(obj='datacenter1')])
                elif method == 'get_object_property':
                    if args == (vim, 'datacenter1', 'network'):
                        return mock.Mock(ManagedObjectReference=objects)
                    elif args == (vim, wrong_pg, 'name'):
                        return 'wrong_pg'
                    elif args == (vim, pg_to_delete, 'name'):
                        return util.DVSController._get_net_name(self.dvs_name,
                                                                fake_network)
                    elif args == (vim, not_pg, 'name'):
                        self.fail('Called with not pg')
            elif module == vim:
                if method == 'Destroy_Task':
                    self.assertEqual((pg_to_delete, ), args)
                    return

            self.fail('Unexpected call. Module: %(module)s; '
                      'method: %(method)s; args: %(args)s, '
                      'kwargs: %(kwargs)s' % {'module': module,
                                              'method': method,
                                              'args': args,
                                              'kwargs': kwargs})

        invoke_api = mock.Mock(side_effect=invoke_api_side_effect)
        connection = mock.Mock(invoke_api=invoke_api, vim=vim)
        return connection


class DVSControllerPortUpdateTestCase(DVSControllerBaseTestCase):

    def test_switch_port_blocked_state(self):
        neutron_port = fake_port.copy()
        neutron_port['admin_state_up'] = False
        dvs_port = mock.Mock()
        dvs_port.config.setting.blocked.value = True

        with mock.patch.object(self.controller, '_get_port_info_by_name',
                               return_value=dvs_port):
            self.controller.switch_port_blocked_state(fake_port)

        self.assertEqual(1, self.connection.invoke_api.call_count)
        self.assertEqual(
            mock.call(
                self.vim, 'ReconfigureDVPort_Task', self.dvs,
                port=mock.ANY),
            self.connection.invoke_api.call_args)
        args, kwargs = self.connection.invoke_api.call_args
        update_spec = kwargs['port'][0]
        self.assertEqual(dvs_port.key, update_spec.key)
        self.assertEqual('edit', update_spec.operation)

        self.assertEqual(1, self.connection.wait_for_task.call_count)

    def _get_connection_mock(self, dvs_name):
        return mock.Mock(vim=self.vim)


class UpdateSecurityGroupRulesTestCase(DVSControllerBaseTestCase):
    BOUND_PORTS = (1, 7, 15)
    UNBOUND_PORT = 123
    PORTGROUP_KEY = 345

    def setUp(self):
        super(UpdateSecurityGroupRulesTestCase, self).setUp()
        self.spec = mock.Mock()
        self.vim.client.factory.create.return_value = self.spec

    def test_update_port_rules(self):
        ports = [fake_port]
        port_info = {'config': {'configVersion': '_config_version_'},
                     'key': '_dvs_port_key_'}
        self.use_patch('mech_vmware_dvs.util.DVSController'
                       '._get_port_info_by_name', return_value=port_info)
        self.use_patch('mech_vmware_dvs.util.DVSController._get_ports',
                       return_value=ports)
        self.controller.update_port_rules(ports)
        self.assertTrue(self.connection.invoke_api.called)
        args, kwargs = self.connection.invoke_api.call_args
        self.assertEqual(self.vim, args[0])
        self.assertEqual('ReconfigureDVPort_Task', args[1])
        self.assertEqual(self.dvs, args[2])
        call_ports = kwargs['port']
        self.assertEqual(len(ports), len(call_ports))
        self.assertEqual('_config_version_', self.spec.configVersion)
        self.assertEqual('_dvs_port_key_', self.spec.key)

    def test__get_ports_for_pg(self):
        pg = mock.Mock()
        self.use_patch('mech_vmware_dvs.util.DVSController'
                       '._get_pg_by_name', return_value=pg)

        some_ports = self.BOUND_PORTS
        with mock.patch.object(self.controller.connection, 'invoke_api',
                               return_value=[some_ports]) as m:
            self.assertEqual(
                some_ports,
                self.controller._get_ports_for_pg('pg_name')
            )
        m.assert_called_once_with(mock.ANY, 'get_object_property', self.vim,
                                  pg, 'portKeys')

    def test__increase_ports_on_portgroup(self):
        ports_number = 8
        pg_info = mock.Mock(numPorts=ports_number,
                            configVersion='_config_version_')
        self.use_patch('mech_vmware_dvs.util.DVSController'
                       '._get_config_by_ref', return_value=pg_info)
        _build_pg_update_spec = self.use_patch(
            'mech_vmware_dvs.util.DVSController._build_pg_update_spec',
            return_value='_update_spec_')
        pg = mock.Mock()
        with mock.patch.object(self.controller.connection, 'invoke_api'):
            self.controller._increase_ports_on_portgroup(pg)

        _build_pg_update_spec.assert_called_once_with(
            '_config_version_',
            ports_number=ports_number * 2)

    def test__increase_ports_on_portgroup_when_pg_dont_have_ports(self):
        ports_number = 0
        pg_info = mock.Mock(numPorts=ports_number,
                            configVersion='_config_version_')
        self.use_patch('mech_vmware_dvs.util.DVSController'
                       '._get_config_by_ref', return_value=pg_info)
        _build_pg_update_spec = self.use_patch(
            'mech_vmware_dvs.util.DVSController._build_pg_update_spec',
            return_value='_update_spec_')
        pg = mock.Mock()
        with mock.patch.object(self.controller.connection, 'invoke_api'):
            self.controller._increase_ports_on_portgroup(pg)

        _build_pg_update_spec.assert_called_once_with('_config_version_',
                                                      ports_number=1)

    def _get_connection_mock(self, dvs_name):
        return mock.Mock(vim=self.vim)


class SpecBuilderTestCase(base.BaseTestCase):

    def setUp(self):
        super(SpecBuilderTestCase, self).setUp()
        self.spec = mock.Mock(name='spec')
        self.factory = mock.Mock(name='factory')
        self.factory.create.return_value = self.spec
        self.builder = util.SpecBuilder(self.factory)

    def test_port_criteria_with_port_key(self):
        criteria = self.builder.port_criteria(port_key='_some_port_')
        self.factory.create.assert_called_once_with(
            'ns0:DistributedVirtualSwitchPortCriteria'
        )
        self.assertEqual(criteria.portKey, '_some_port_')
        self.assertNotIn('portgroupKey', dir(criteria))

    def test_port_criteria_with_port_group_key(self):
        criteria = self.builder.port_criteria(port_group_key='_port_group_key')
        self.factory.create.assert_called_once_with(
            'ns0:DistributedVirtualSwitchPortCriteria'
        )
        self.assertEqual(criteria.portgroupKey, '_port_group_key')
        self.assertEqual(criteria.inside, '1')
        self.assertNotIn('portKey', dir(criteria))

    def test__create_rule_egress(self):
        rule = self._create_rule(direction='egress')
        self.assertEqual(rule.direction, 'outgoingPackets')

    def test__create_rule_ingress(self):
        rule = self._create_rule(direction='ingress')
        self.assertEqual(rule.direction, 'incomingPackets')

    def test__create_rule_ingress_port_range(self):
        rule = self._create_rule(direction='ingress',
                                 port_range_min=22,
                                 port_range_max=23)
        qualifier = rule.qualifier[0]
        self.assertEqual(qualifier.sourceIpPort.startPortNumber, 32768)
        self.assertEqual(qualifier.sourceIpPort.endPortNumber, 65535)
        self.assertEqual(qualifier.destinationIpPort.startPortNumber, 22)
        self.assertEqual(qualifier.destinationIpPort.endPortNumber, 23)

    def test__create_rule_egress_port_range(self):
        rule = self._create_rule(direction='egress',
                                 port_range_min=22,
                                 port_range_max=23)
        qualifier = rule.qualifier[0]
        self.assertEqual(qualifier.destinationIpPort.startPortNumber, 22)
        self.assertEqual(qualifier.destinationIpPort.endPortNumber, 23)

    def test__create_rule_ingress_cidr(self):
        rule = self._create_rule(direction='ingress',
                                 source_ip_prefix='192.168.0.1/24')
        qualifier = rule.qualifier[0]
        self.assertEqual('192.168.0.1', qualifier.sourceAddress.addressPrefix)
        self.assertEqual('0.0.0.0', qualifier.destinationAddress.addressPrefix)

    def test__create_rule_egress_cidr(self):
        rule = self._create_rule(direction='egress',
                                 dest_ip_prefix='192.168.0.1/24')
        qualifier = rule.qualifier[0]
        self.assertEqual('192.168.0.1',
                         qualifier.destinationAddress.addressPrefix)
        self.assertEqual('0.0.0.0', qualifier.sourceAddress.addressPrefix)

    def test__create_rule_egress_ip(self):
        rule = self._create_rule(direction='egress',
                                 dest_ip_prefix='192.168.0.1/24',
                                 ip='10.20.0.2')
        qualifier = rule.qualifier[0]
        self.assertEqual('10.20.0.2',
                         qualifier.destinationAddress.address)
        self.assertEqual('0.0.0.0', qualifier.sourceAddress.addressPrefix)

    def test__create_rule_ingress_ip(self):
        rule = self._create_rule(direction='ingress',
                                 dest_ip_prefix='192.168.0.1/24',
                                 ip='10.20.0.2')
        qualifier = rule.qualifier[0]
        self.assertEqual('0.0.0.0',
                         qualifier.destinationAddress.addressPrefix)
        self.assertEqual('10.20.0.2', qualifier.sourceAddress.address)

    def _create_rule(self, ip=None, **kwargs):
        def side_effect(name):
            return mock.Mock(name=name)

        self.factory.create.side_effect = side_effect

        rule_info = {'direction': 'egress',
                     'protocol': 'tcp',
                     'ethertype': 'IPv4'}

        sequence = 25
        rule_info.update(kwargs)
        rule = self.builder._create_rule(rule_info, ip)
        result = rule.build(sequence)
        self.assertEqual(result.sequence, sequence)
        return result


class TrafficRuleBuilderBaseTestCase(UtilBaseTestCase):

    def setUp(self):
        super(TrafficRuleBuilderBaseTestCase, self).setUp()
        self.spec_factory = self._get_factory_mock((
            'ns0:IntExpression',
            'ns0:DvsTrafficRule',
            'ns0:DvsAcceptNetworkRuleAction',
            'ns0:DvsIpNetworkRuleQualifier',
            'ns0:IpRange',
            'ns0:SingleIp',
            'ns0:DvsSingleIpPort',
            'ns0:DvsIpPortRange'))


class TrafficRuleBuilderTestCase(TrafficRuleBuilderBaseTestCase):
    def setUp(self):
        super(TrafficRuleBuilderTestCase, self).setUp()
        self.sequence = 20

    def _create_builder(self, ethertype=None, protocol=None, name=None):
        class ConcreteTrafficRuleBuilder(util.TrafficRuleBuilder):

            def port_range(self, start, end):
                pass

            def cidr(self, cidr):
                pass

        return ConcreteTrafficRuleBuilder(
            self.spec_factory, ethertype, protocol, name)

    def test_build_sequence(self):
        name = '_name_'
        builder = self._create_builder(name=name)
        rule = builder.build(self.sequence)
        self.assertEqual(self.sequence, rule.sequence)
        self.assertEqual(str(self.sequence) + '. ' + name, rule.description)

    def test_build_ethertype_IPv4(self):
        builder = self._create_builder(ethertype='IPv4')
        rule = builder.build(self.sequence)
        qualifier = rule.qualifier[0]
        self.assertEqual('0.0.0.0', qualifier.sourceAddress.addressPrefix)
        self.assertEqual('0', qualifier.sourceAddress.prefixLength)
        self.assertEqual('0.0.0.0', qualifier.destinationAddress.addressPrefix)
        self.assertEqual('0', qualifier.destinationAddress.prefixLength)

    def test_build_ethertype_IPv6(self):
        builder = self._create_builder(ethertype='IPv6')
        rule = builder.build(self.sequence)
        qualifier = rule.qualifier[0]
        self.assertEqual('::', qualifier.sourceAddress.addressPrefix)
        self.assertEqual('0', qualifier.sourceAddress.prefixLength)
        self.assertEqual('::', qualifier.destinationAddress.addressPrefix)
        self.assertEqual('0', qualifier.destinationAddress.prefixLength)

    def test_build_ethertype_protocol(self):
        for name, rfc in util.PROTOCOL.iteritems():
            builder = self._create_builder(protocol=name)
            rule = builder.build(self.sequence)
            qualifier = rule.qualifier[0]
            self.assertEqual(rfc,
                             qualifier.protocol.value,
                             'Wrong value for %s protocol' % name)

        builder = self._create_builder(protocol='not_described')
        rule = builder.build(self.sequence)
        qualifier = rule.qualifier[0]
        self.assertEqual('not_described',
                         qualifier.protocol.value)

    def test__has_port_for_icmp(self):
        builder = self._create_builder(protocol='icmp')
        self.assertFalse(builder._has_port(None))
        self.assertFalse(builder._has_port(123))

    def test__has_port_for_tcp(self):
        builder = self._create_builder(protocol='tcp')
        self.assertFalse(builder._has_port(None))
        self.assertTrue(builder._has_port(123))

    def test__cidr_spec_for_ip_range(self):
        builder = self._create_builder()
        cidr_spec = builder._cidr_spec('192.168.0.2/24')
        self.assertEqual('ns0:IpRange', cidr_spec._mock_name)
        self.assertEqual('192.168.0.2', cidr_spec.addressPrefix)
        self.assertEqual('24', cidr_spec.prefixLength)

    def test__cidr_spec_for_single_ip(self):
        builder = self._create_builder()
        cidr_spec = builder._cidr_spec('192.168.0.2')
        self.assertEqual('ns0:SingleIp', cidr_spec._mock_name)
        self.assertEqual('192.168.0.2', cidr_spec.address)

    def test__port_spec_for_single_port(self):
        builder = self._create_builder()
        port_spec = builder._port_range_spec(22, 22)
        self.assertEqual('ns0:DvsSingleIpPort', port_spec._mock_name)
        self.assertEqual(22, port_spec.portNumber)

    def test__port_spec_for_port_range(self):
        builder = self._create_builder()
        port_spec = builder._port_range_spec(22, 121)
        self.assertEqual('ns0:DvsIpPortRange', port_spec._mock_name)
        self.assertEqual(22, port_spec.startPortNumber)
        self.assertEqual(121, port_spec.endPortNumber)


class UtilTestCase(base.BaseTestCase):
    """TestCase for functions in util module"""

    def setUp(self):
        super(UtilTestCase, self).setUp()
        patch = mock.patch('oslo_vmware.api.VMwareAPISession',
                           return_value='session')
        self.session_mock = patch.start()
        self.addCleanup(patch.stop)

    def test_empty_map_if_config_network_maps_is_empty(self):
        CONF.set_override('network_maps', [], 'ml2_vmware')
        self.assertDictEqual(
            {},
            util.create_network_map_from_config(CONF.ml2_vmware))

    @mock.patch('mech_vmware_dvs.util.DVSController._get_dvs',
                return_value=(mock.Mock(), 'datacenter1'))
    def test_creates_network_map_from_conf(self, *args):
        network_map = ['physnet1:dvSwitch', 'physnet2:dvSwitch1']
        CONF.set_override(
            'network_maps', network_map, 'ml2_vmware')
        actual = util.create_network_map_from_config(CONF.ml2_vmware)

        self.assertEqual(len(network_map), len(actual))

        for net, dvs_name in [i.split(':') for i in network_map]:
            controller = actual[net]
            self.assertEqual('session', controller.connection)

        vmware_conf = config.CONF.ml2_vmware
        self.session_mock.assert_called_once_with(
            vmware_conf.vsphere_hostname,
            vmware_conf.vsphere_login,
            vmware_conf.vsphere_password,
            vmware_conf.api_retry_count,
            vmware_conf.task_poll_interval)

    def test_wrap_retry_w_login_unsuccessful(self):
        func = mock.Mock()

        def side_effect(*args, **kwargs):
            exception = vmware_exceptions.VMwareDriverException()
            exception.message = util.LOGIN_PROBLEM_TEXT
            raise exception

        func.side_effect = side_effect

        def double(*args, **kwargs):
            return func(*args, **kwargs)

        self.assertRaises(
            vmware_exceptions.VMwareDriverException, util.wrap_retry(double))
        self.assertEqual(3, func.call_count)
