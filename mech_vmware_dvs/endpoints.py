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

import abc
import re

import six
from oslo_concurrency import lockutils
from neutron import manager
from neutron.context import Context
from neutron.plugins.ml2 import driver_context

FAKE_PORT_ID = 'fake_id'


@six.add_metaclass(abc.ABCMeta)
class EndPointBase(object):
    event_type_regex = None

    def __init__(self, driver):
        self.driver = driver

    @lockutils.synchronized('vmware_dvs_info', external=True)
    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        if re.match(self.event_type_regex, event_type):
            self._execute(ctxt, payload)

    @abc.abstractmethod
    def _execute(self, ctxt, payload):
        pass

    def update_security_group(self, ctxt, security_group_id):
        plugin_context = Context.from_dict(ctxt)
        plugin = manager.NeutronManager.get_plugin()
        fake_network = {
            'id': 'fake'
        }
        fake_port = {
            'id': FAKE_PORT_ID,
            'security_groups': [security_group_id]
        }
        context = driver_context.PortContext(
            plugin, plugin_context, fake_port, fake_network, None, None
        )
        for dvs in self.driver.network_map.values():
            self.driver._update_security_groups(dvs, context, force=True)


class SecurityGroupRuleCreateEndPoint(EndPointBase):
    event_type_regex = r'security_group_rule\.create\.end'

    def _execute(self, ctxt, payload):
        security_group_rule_id = payload['security_group_rule']['id']
        security_group_id = payload['security_group_rule']['security_group_id']
        self.driver.sgr_to_sg[security_group_rule_id] = security_group_id
        self.update_security_group(ctxt, security_group_id)


class SecurityGroupRuleDeleteEndPoint(EndPointBase):
    event_type_regex = r'security_group_rule\.delete\.end'

    def __init__(self, driver):
        super(SecurityGroupRuleDeleteEndPoint, self).__init__(driver)

    def _execute(self, ctxt, payload):
        security_group_rule_id = payload['security_group_rule_id']
        security_group_id = self.driver.sgr_to_sg.pop(security_group_rule_id)
        self.update_security_group(ctxt, security_group_id)


class SecurityGroupCreateEndPoint(EndPointBase):
    event_type_regex = r'security_group\.create\.end'

    def _execute(self, ctxt, payload):
        for rule in payload['security_group_rules']:
            self.driver.sgr_to_sg[rule['id']] = payload['id']


class SecurityGroupDeleteEndPoint(EndPointBase):
    event_type_regex = r'security_group\.delete\.end'

    def _execute(self, ctxt, payload):
        for sgr_id, sg_id in self.driver.sgr_to_sg.items():
            if sg_id == payload['security_group_id']:
                del self.driver.sgr_to_sg[sgr_id]
