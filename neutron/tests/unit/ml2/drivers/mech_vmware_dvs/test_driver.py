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

from neutron.plugins.ml2.drivers.mech_vmware_dvs import config
from neutron.plugins.ml2.drivers.mech_vmware_dvs import driver
from neutron.plugins.ml2.drivers.mech_vmware_dvs import exceptions
from neutron.tests import base


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

    @mock.patch('neutron.plugins.ml2.drivers.mech_vmware_dvs.util'
                '.create_network_map_from_config', return_value='network_map')
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
            self.assertRaises(exceptions.NotSupportedNetworkType,
                              self.driver.create_network_precommit, context)
            self.assertEqual(0, self.dvs.create_network.call_count,
                             "Should not support %s" % type_)

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
            self.assertRaises(exceptions.NotSupportedNetworkType,
                              self.driver.update_network_precommit, context)
            self.assertEqual(0, self.dvs.update_network.call_count,
                             "Should not support %s" % type_)

    def test_delete_network_postcommit(self):
        context = self._create_network_context()
        self.driver.delete_network_postcommit(context)
        self.dvs.delete_network.assert_called_once_with(context.current)

    def test_delete_network_postcommit_dont_support_other_network_type(self):
        for type_ in NOT_SUPPORTED_TYPES:
            context = self._create_network_context(type_)
            self.assertRaises(exceptions.NotSupportedNetworkType,
                              self.driver.delete_network_postcommit, context)
            self.assertEqual(0, self.dvs.delete_network.call_count,
                             "Should not support %s" % type_)

    def test_delete_network_postcommit_when_network_is_not_mapped(self):
        context = self._create_network_context()
        self.driver.network_map = {}
        try:
            self.driver.delete_network_postcommit(context)
        except Exception:
            self.fail('Should not throw any exceptions')

    @mock.patch(
        'neutron.plugins.ml2.drivers.mech_vmware_dvs.compute_util'
        '.get_hypervisors_by_host')
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

    @mock.patch(
        'neutron.plugins.ml2.drivers.mech_vmware_dvs.compute_util'
        '.get_hypervisors_by_host')
    def test_bind_port_other_hypervisor(self, get_hypervisor):
        context = self._create_port_context()
        get_hypervisor.return_value = mock.Mock(
            hypervisor_type=INVALID_HYPERVISOR_TYPE)

        self.driver.bind_port(context)
        self.assertFalse(context.set_binding.called)

    @mock.patch(
        'neutron.plugins.ml2.drivers.mech_vmware_dvs.compute_util'
        '.get_hypervisors_by_host', side_effect=exceptions.HypervisorNotFound)
    def test_bind_port_hypervisor_not_found(self, get_hypervisor):
        context = self._create_port_context()

        self.driver.bind_port(context)
        self.assertFalse(context.set_binding.called)

    def _create_port_context(self):
        return mock.Mock(
            current={
                'binding:host_id': '_id_server_'},
            network=self._create_network_context())

    def _create_network_context(self, network_type='vlan'):
        return mock.Mock(current={'id': 'id'},
                         network_segments=[
                             {'id': '_id_segment_',
                              'network_type': network_type,
                              'physical_network': 'physnet1'}])
