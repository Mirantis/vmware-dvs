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

import mock
from neutron.tests import base
from neutron.context import Context

from mech_vmware_dvs import endpoints

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


class EndPointBaseTestCase(base.BaseTestCase):
    def setUp(self):
        class ConcreteEndPoint(endpoints.EndPointBase):
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
                port, {'id': endpoints.FAKE_PORT_ID,
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
                'id': '_dummy_id_',
                'security_group_id': '_dummy_security_group_id_'}}
        self.driver = mock.Mock(sgr_to_sg={})
        self.endpoint = endpoints.SecurityGroupRuleCreateEndPoint(self.driver)

    @mock.patch('mech_vmware_dvs.endpoints.SecurityGroupRuleCreateEndPoint'
                '.update_security_group')
    def test_info(self, update_security_group):
        self.endpoint.info(fake_endpoint_context, '_publisher_id_',
                           '_event_type_', self.payload, '_metadata_')
        update_security_group.assert_called_once_with(
            fake_endpoint_context,
            '_dummy_security_group_id_')
        self.assertEqual('_dummy_security_group_id_',
                         self.driver.sgr_to_sg['_dummy_id_'])


class SecurityGroupRuleDeleteEndPointTestCase(base.BaseTestCase):
    def setUp(self):
        super(SecurityGroupRuleDeleteEndPointTestCase, self).setUp()
        self.payload = {
            'security_group_rule_id': '_security_group_rule_id_'}
        self.driver = mock.Mock(sgr_to_sg={})
        self.endpoint = endpoints.SecurityGroupRuleDeleteEndPoint(self.driver)

    @mock.patch('mech_vmware_dvs.endpoints.SecurityGroupRuleDeleteEndPoint'
                '.update_security_group')
    def test_info(self, update_security_group):
        self.driver.sgr_to_sg[
            '_security_group_rule_id_'] = '_dummy_security_group_id_'
        self.endpoint.info(fake_endpoint_context, '_publisher_id_',
                           '_event_type_.end', self.payload, '_metadata_')
        update_security_group.assert_called_once_with(
            fake_endpoint_context,
            '_dummy_security_group_id_')
        self.assertEqual({}, self.driver.sgr_to_sg)
