# Copyright 2010-2011 OpenStack Foundation
# Copyright 2012-2013 IBM Corp.
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


class VMwareDVSMechanismDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(VMwareDVSMechanismDriverTestCase, self).setUp()
        self.driver = driver.VMwareDVSMechanismDriver()
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

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test_update_port_postcommit(self, hypervisor_by_host):
        hypervisor_by_host.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)
        port_context = self._create_port_context()

        self.driver.update_port_postcommit(port_context)
        self.assertEqual(
            self.dvs.switch_port_blocked_state.call_args_list,
            [mock.call(port_context.current)])

    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._is_port_belong_to_vmware')
    def test_update_port_postcommit_invalid_port(self, is_valid_port):
        is_valid_port.return_value = False

        self.driver.update_port_postcommit(self._create_port_context())

        self.assertTrue(is_valid_port.called)
        self.assertFalse(self.dvs.switch_port_blocked_state.called)

    @mock.patch('mech_vmware_dvs.driver.VMwareDVSMechanismDriver'
                '._is_port_belong_to_vmware')
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

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test_bind_port(self, get_hypervisor):
        context = self._create_port_context()
        get_hypervisor.return_value = mock.Mock(
            hypervisor_type=VALID_HYPERVISOR_TYPE)

        self.driver.bind_port(context)

        self.assertEqual(
            context.set_binding.call_count,
            len(context.network.network_segments))
        for idx, segment in enumerate(context.network.network_segments):
            self.assertEqual(
                context.set_binding.call_args_list[idx],
                mock.call(
                    segment['id'],
                    self.driver.vif_type, self.driver.vif_details,
                    status='ACTIVE'))

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test__is_port_belong_to_vmware__unbinded_port(self, get_hypervisor):
        context = self._create_port_context()
        port = context.current
        port.pop('binding:host_id')

        result = self.driver._is_port_belong_to_vmware(context.current)
        self.assertFalse(result)

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test__is_port_belong_to_vmware__invalid_hypervisor(
            self, get_hypervisor):
        context = self._create_port_context()
        get_hypervisor.return_value = mock.Mock(
            hypervisor_type=INVALID_HYPERVISOR_TYPE)

        result = self.driver._is_port_belong_to_vmware(context.current)
        self.assertFalse(result)

    @mock.patch('mech_vmware_dvs.compute_util.get_hypervisors_by_host')
    def test__is_port_belong_to_vmware__not_found(self, get_hypervisor):
        get_hypervisor.side_effect = exceptions.HypervisorNotFound
        context = self._create_port_context()

        result = self.driver._is_port_belong_to_vmware(context.current)
        self.assertTrue(get_hypervisor.called)
        self.assertFalse(result)

    def _create_port_context(self):
        return mock.Mock(
            current={
                'id': '_dummy_port_id_',
                'binding:host_id': '_id_server_'},
            network=self._create_network_context())

    def _create_network_context(self, network_type='vlan'):
        return mock.Mock(current={'id': '_dummy_net_id_'},
                         network_segments=[
                             {'id': '_id_segment_',
                              'network_type': network_type,
                              'physical_network': 'physnet1'}])
