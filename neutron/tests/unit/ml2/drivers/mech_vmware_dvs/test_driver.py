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

from neutron.plugins.ml2.drivers.mech_vmware_dvs import config

from neutron.plugins.ml2.drivers.mech_vmware_dvs import driver
from neutron.plugins.ml2.drivers.mech_vmware_dvs import exceptions
from neutron.tests import base


class VMwareDVSMechanismBaseTestCase(base.BaseTestCase):
    def setUp(self):
        super(VMwareDVSMechanismBaseTestCase, self).setUp()
        self.driver = driver.VMwareDVSMechanismDriver()

    @mock.patch('neutron.plugins.ml2.drivers.mech_vmware_dvs.util'
                '.create_network_map_from_config', return_value='network_map')
    def test_initialize(self, m):
        self.driver.initialize()
        m.assert_called_once_with(config.CONF.ml2_vmware)
        self.assertEqual('network_map', self.driver.network_map)

    def test_create_network_precommit(self):
        dvs = mock.Mock()
        context = self.create_network()
        self.driver.network_map = {'physnet1': dvs}
        self.driver.create_network_precommit(context)
        dvs.create_network.assert_called_once_with('current',
                                                   context.network_segments[0])

    def test_create_network_precommit_dont_support_other_network_type(self):
        for type_ in ('gre', 'vxlan'):
            dvs = mock.Mock()
            context = self.create_network(type_)
            self.assertRaises(exceptions.NotSupportedNetworkTypeException,
                              self.driver.create_network_precommit, context)
            self.assertEqual(0, dvs.create_network.call_count,
                             "Should not support %s" % type_)

    def test_create_network_precommit_when_not_network_not_mapped(self):
        dvs = mock.Mock()
        context = self.create_network()
        self.driver.network_map = {}
        self.driver.create_network_precommit(context)
        self.assertEqual(0, dvs.create_network.call_count)

    def create_network(self, network_type='vlan'):
        return mock.Mock(current='current',
                         network_segments=[
                             {'network_type': network_type,
                              'physical_network': 'physnet1'}])
