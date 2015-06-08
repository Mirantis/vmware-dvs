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

import string

import fixtures
import mock
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util

from mech_vmware_dvs import config
from mech_vmware_dvs import exceptions
from mech_vmware_dvs import util
from neutron.tests import base


CONF = config.CONF

fake_network = {'id': '34e33a31-516a-439f-a186-96ac85155a8c',
                'name': '_fake_network_',
                'admin_state_up': True}
fake_segment = {'segmentation_id': '102'}
fake_port = {
    'id': '_dummy_port_id_',
    'admin_state_up': True,
    'device_id': '_dummy_server_id_'}

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


class DVSControllerBaseTestCase(base.BaseTestCase):
    """Base of all DVSController tests"""

    def setUp(self):
        super(DVSControllerBaseTestCase, self).setUp()
        self.dvs_name = 'dvs_name'
        self.vim = mock.Mock()
        self.connection = self._get_connection_mock(self.dvs_name)
        self.controller = util.DVSController(self.dvs_name,
                                             self.connection)

    def _get_connection_mock(self, dvs_name):
        raise NotImplementedError


class DVSControllerTestCase(DVSControllerBaseTestCase):
    """Tests of DVSController that don't call API methods"""

    def test_creation(self):
        self.assertEqual(self.dvs_name, self.controller.dvs_name)
        self.assertIs(self.connection, self.controller.connection)

    def test__get_vm_by_uuid(self):
        self.connection.invoke_api.return_value = [mock.sentinel.vm_by_uuid]
        uuid = '_dummy_vm_uuid_'

        vm = self.controller._get_vm_by_uuid(uuid)

        self.assertEqual(mock.sentinel.vm_by_uuid, vm)
        self.assertEqual([
            mock.call(
                self.vim, 'FindAllByUuid', mock.ANY,
                uuid=uuid, vmSearch=True, instanceUuid=True)],
            self.connection.invoke_api.call_args_list)

    def test__get_vm_by_uuid__not_found(self):
        self.connection.invoke_api.return_value = []
        uuid = '_dummy_vm_uuid_'

        self.assertRaises(
            exceptions.VMNotFound, self.controller._get_vm_by_uuid, uuid)

    def test__get_port_by_neutron_uuid__not_found1(self):
        dvs_ref = mock.sentinel.dvs_ref
        vm_ref = mock.sentinel.vm_ref
        vm_uuid = '_dummy_vm_uuid_'
        vm_config = mock.Mock()
        vm_config.extraConfig = []

        with mock.patch.object(
                self.controller, '_get_config_by_ref', return_value=vm_config):
            self.assertRaises(
                exceptions.PortNotFound,
                self.controller._get_port_by_neutron_uuid, dvs_ref, vm_ref,
                vm_uuid)

    def test__get_port_by_neutron_uuid__not_found2(self):
        dvs_ref = mock.sentinel.dvs_ref
        vm_ref = mock.sentinel.vm_ref
        vm_uuid = '_dummy_vm_uuid_'
        vm_config = mock.Mock()
        vm_config.extraConfig = [
            mock.Mock(key='nvp.iface-id.0', value=vm_uuid)]
        vm_config.hardware.device = []

        with mock.patch.object(
                self.controller, '_get_config_by_ref', return_value=vm_config):
            self.assertRaises(
                exceptions.PortNotFound,
                self.controller._get_port_by_neutron_uuid, dvs_ref, vm_ref,
                vm_uuid)

    def test__get_port_by_neutron_uuid__not_found3(self):
        dvs_ref = mock.sentinel.dvs_ref
        vm_ref = mock.sentinel.vm_ref
        vm_uuid = '_dummy_vm_uuid_'
        vm_config = mock.Mock()
        vm_config.extraConfig = [
            mock.Mock(key='nvp.iface-id.0', value=vm_uuid)]
        vm_config.hardware.device = [
            self.VirtualE1000('16', '_fake_switch_uuid_')]

        with mock.patch.object(
                self.controller, '_get_config_by_ref', return_value=vm_config):
            self.assertRaises(
                exceptions.PortNotFound,
                self.controller._get_port_by_neutron_uuid, dvs_ref, vm_ref,
                vm_uuid)

    def test__get_port_by_neutron_uuid__not_found4(self):
        dvs_ref = mock.sentinel.dvs_ref
        dvs_uuid = '_dummy_dvs_uuid_'
        vm_ref = mock.sentinel.vm_ref
        vm_uuid = '_dummy_vm_uuid_'
        vm_config = mock.Mock()
        vm_config.extraConfig = [
            mock.Mock(key='nvp.iface-id.0', value=vm_uuid)]
        vm_config.hardware.device = [
            self.VirtualE1000('16', dvs_uuid)]

        def _invoke_api_handler(module, method, *args, **kwargs):
            if (vim_util, 'get_object_property') == (module, method) \
                    and args[1:] == (dvs_ref, 'uuid'):
                return dvs_uuid
            elif (self.vim, 'FetchDVPorts') == (module, method) \
                    and (dvs_ref,) == args[:1]:
                return []
            return mock.Mock()

        self.connection.invoke_api.side_effect = _invoke_api_handler

        with mock.patch.object(
                self.controller, '_get_config_by_ref', return_value=vm_config):
            self.assertRaises(
                exceptions.PortNotFound,
                self.controller._get_port_by_neutron_uuid, dvs_ref, vm_ref,
                vm_uuid)
            return

    def test__get_port_by_neutron_uuid(self):
        dvs_ref = mock.sentinel.dvs_ref
        dvs_uuid = '_dummy_dvs_uuid_'
        vm_ref = mock.sentinel.vm_ref
        vm_uuid = '_dummy_vm_uuid_'
        vm_config = mock.Mock()
        vm_config.extraConfig = [
            mock.Mock(key='nvp.iface-id.0', value=vm_uuid)]
        vm_config.hardware.device = [
            self.VirtualE1000('16', dvs_uuid)]

        dummy_dvs_port = mock.sentinel.dvs_port

        def _invoke_api_handler(module, method, *args, **kwargs):
            if (vim_util, 'get_object_property') == (module, method) \
                    and args[1:] == (dvs_ref, 'uuid'):
                return dvs_uuid
            elif (self.vim, 'FetchDVPorts') == (module, method) \
                    and (dvs_ref,) == args[:1]:
                return [dummy_dvs_port]
            return mock.Mock()

        self.connection.invoke_api.side_effect = _invoke_api_handler

        with mock.patch.object(
                self.controller, '_get_config_by_ref', return_value=vm_config):
            result = self.controller._get_port_by_neutron_uuid(
                dvs_ref, vm_ref, vm_uuid)

            self.assertEqual(dummy_dvs_port, result)
            self.assertEqual(
                mock.call(
                    self.vim, 'FetchDVPorts', dvs_ref, criteria=mock.ANY),
                self.connection.invoke_api.call_args_list[-1])

    def test__get_net_name(self):
        expect = fake_network['name'] + '-' + fake_network['id']
        self.assertEqual(expect, self.controller._get_net_name(fake_network))

    def test__get_net_name_without_name(self):
        net = fake_network.copy()
        net.pop('name')
        self.assertEqual(net['id'], self.controller._get_net_name(net))

    def test__get_net_name_illegal_characters(self):
        illegal_chars = {chr(code) for code in range(128)}
        illegal_chars -= set(string.letters)
        illegal_chars -= set(string.digits)
        illegal_chars.discard('-')
        illegal_chars.discard('_')

        for char in illegal_chars:
            net = fake_network.copy()
            net['name'] = char
            self.assertRaises(
                exceptions.InvalidNetworkName,
                self.controller._get_net_name, net)

    def test__get_net_name_too_long(self):
        net = fake_network.copy()
        max_len = max(0, 80 - len(net['id']) - 1)
        net['name'] = 'x' * max_len
        try:
            self.controller._get_net_name(net)
        except exceptions.InvalidNetworkName:
            self.fail((
                'Invalid maximum name limit. %d chars should still be '
                'allowed') % max_len)

        net['name'] += 'A'
        self.assertRaises(
            exceptions.InvalidNetworkName, self.controller._get_net_name, net)

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
            self.assertEqual(6, self.connection.invoke_api.call_count)
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

    def test_create_network_raises_DVSNotFoundException(self):
        org_side_effect = self.connection.invoke_api.side_effect
        vim = self.vim

        def side_effect(module, method, *args, **kwargs):
            if args == (vim, 'network_folder1', 'childEntity'):
                return mock.Mock(ManagedObjectReference=[])
            else:
                return org_side_effect(module, method, *args, **kwargs)

        self.connection.invoke_api.side_effect = side_effect
        self.assertRaises(exceptions.DVSNotFound,
                          self.controller.create_network,
                          fake_network,
                          fake_segment)

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
        def create_side_effect(namespace):
            if namespace in ('ns0:DVPortgroupConfigSpec',
                             'ns0:VMwareDVSPortSetting',
                             'ns0:VmwareDistributedVirtualSwitchVlanIdSpec',
                             'ns0:BoolPolicy',
                             'ns0:DVPortgroupConfig',
                             'ns0:DVPortgroupPolicy'):
                return mock.Mock(name=namespace)
            else:
                self.fail('Unexpected call. Namespace: %s' % namespace)

        vim = self.vim
        vim.client.factory.create.side_effect = create_side_effect
        controlled_dvs = mock.Mock(_type='VmwareDistributedVirtualSwitch',
                                   name='controlled_dvs')
        wrong_dvs = mock.Mock(_type='VmwareDistributedVirtualSwitch',
                              name='wrong_dvs')
        not_dvs = mock.Mock(_type='not_dvs', name='not_dvs')
        objects = [wrong_dvs, controlled_dvs, not_dvs]

        def invoke_api_side_effect(module, method, *args, **kwargs):
            if module is vim_util:
                if method == 'get_objects':
                    if args == (vim, 'Datacenter', 100, ['name']):
                        return mock.Mock(objects=[
                            mock.Mock(obj='datacenter1')
                        ])
                elif method == 'get_object_property':
                    if args == (vim, 'datacenter1', 'networkFolder'):
                        return 'network_folder1'
                    elif args == (vim, 'network_folder1', 'childEntity'):
                        return mock.Mock(ManagedObjectReference=objects)
                    elif args == (vim, wrong_dvs, 'name'):
                        return 'wrong_dvs'
                    elif args == (vim, controlled_dvs, 'name'):
                        return dvs_name
                    elif args == (vim, not_dvs, 'name'):
                        self.fail('Called with not dvs')
            elif module == vim:
                if method == 'CreateDVPortgroup_Task':
                    self.assertEqual((controlled_dvs,), args)
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
            self.controller._get_net_name(fake_network), spec.name)
        self.assertEqual(util.DVS_PORTS_NUMBER, spec.numPorts)
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
            self.assertEqual(6, self.connection.invoke_api.call_count)
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
        def create_side_effect(namespace):
            if namespace in ('ns0:BoolPolicy',
                             'ns0:VMwareDVSPortSetting',
                             'ns0:DVPortgroupConfigSpec',
                             ):
                return mock.Mock(name=namespace)
            else:
                self.fail('Unexpected call. Namespace: %s' % namespace)

        vim = self.vim
        vim.client.factory.create.side_effect = create_side_effect

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
                        return util.DVSController._get_net_name(fake_network)
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
            self.assertEqual(5, self.connection.invoke_api.call_count)
            self.assertEqual(1, self.connection.wait_for_task.call_count)

    def test_delete_network_raises_VMWareDVSException(self):
        # first we count calls
        self.controller.delete_network(fake_network)
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
                              controller.delete_network, fake_network)

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
                        return util.DVSController._get_net_name(fake_network)
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
    def setUp(self):
        super(DVSControllerPortUpdateTestCase, self).setUp()

        self._dvs_ref = mock.Mock()
        self.useFixture(fixtures.MonkeyPatch(
            'mech_vmware_dvs.util.DVSController._get_dvs',
            mock.Mock(return_value=self._dvs_ref)))

        self._lookup_vm_by_uuid = mock.Mock()
        self.useFixture(fixtures.MonkeyPatch(
            'mech_vmware_dvs.util.DVSController._get_vm_by_uuid',
            self._lookup_vm_by_uuid))

    def test_switch_port_blocked_state(self):
        neutron_port = fake_port.copy()
        neutron_port['admin_state_up'] = False
        dvs_port = mock.Mock()
        dvs_port.config.setting.blocked.value = True

        with mock.patch.object(
                self.controller, '_get_port_by_neutron_uuid',
                return_value=dvs_port):

            self.controller.switch_port_blocked_state(fake_port)

            self.assertEqual(1, self.connection.invoke_api.call_count)
            self.assertEqual(
                mock.call(
                    self.vim, 'ReconfigureDVPort_Task', self._dvs_ref,
                    port=mock.ANY),
                self.connection.invoke_api.call_args)
            args, kwargs = self.connection.invoke_api.call_args
            update_spec = kwargs['port'][0]
            self.assertEqual(dvs_port.key, update_spec.key)
            self.assertEqual('edit', update_spec.operation)

            self.assertEqual(1, self.connection.wait_for_task.call_count)

    def test_switch_port_blocked_state__noop(self):
        neutron_port = fake_port.copy()
        neutron_port['admin_state_up'] = False
        dvs_port = mock.Mock()
        dvs_port.config.setting.blocked.value = False

        with mock.patch.object(
                self.controller, '_get_port_by_neutron_uuid',
                return_value=dvs_port):

            self.controller.switch_port_blocked_state(fake_port)

            self.assertFalse(self.connection.invoke_api.called)

    def _get_connection_mock(self, dvs_name):
        return mock.Mock(vim=self.vim)


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

    def test_cretes_network_map_from_conf(self):
        network_map = ['physnet1:dvSwitch', 'physnet2:dvSwitch1']
        CONF.set_override(
            'network_maps', network_map, 'ml2_vmware')
        actual = util.create_network_map_from_config(CONF.ml2_vmware)

        self.assertEqual(len(network_map), len(actual))

        for net, dvs_name in [i.split(':') for i in network_map]:
            controller = actual[net]
            self.assertEqual(dvs_name, controller.dvs_name)
            self.assertEqual('session', controller.connection)

        vmware_conf = config.CONF.ml2_vmware
        self.session_mock.assert_called_once_with(
            vmware_conf.vsphere_hostname,
            vmware_conf.vsphere_login,
            vmware_conf.vsphere_password,
            vmware_conf.api_retry_count,
            vmware_conf.task_poll_interval)
