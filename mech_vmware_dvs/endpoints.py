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
from neutron.db import api as db
from neutron.db import securitygroups_db
from neutron import manager
from neutron.context import Context
from neutron.plugins.ml2 import driver_context

FAKE_PORT_ID = 'fake_id'


@six.add_metaclass(abc.ABCMeta)
class EndPointBase(object):
    event_type_regex = None

    def __init__(self, driver):
        self.driver = driver

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        if re.match(self.event_type_regex, event_type):
            self._execute(ctxt, payload)

    @abc.abstractmethod
    def _execute(self, ctxt, payload):
        pass

    def update_security_group(self, ctxt, *security_group_ids):
        plugin_context = Context.from_dict(ctxt)
        plugin = manager.NeutronManager.get_plugin()
        fake_network = {
            'id': 'fake'
        }
        fake_port = {
            'id': FAKE_PORT_ID,
            'security_groups': security_group_ids
        }
        context = driver_context.PortContext(
            plugin, plugin_context, fake_port, fake_network, None, None
        )
        for dvs in self.driver.network_map.values():
            self.driver._update_security_groups(dvs, context, force=True)


class SecurityGroupRuleCreateEndPoint(EndPointBase):
    event_type_regex = r'security_group_rule\.create\.end'

    def _execute(self, ctxt, payload):
        security_group_id = payload['security_group_rule']['security_group_id']
        self.update_security_group(ctxt, security_group_id)


class SecurityGroupRuleDeleteEndPoint(EndPointBase):
    event_type_regex = r'security_group_rule\.delete\.end'

    def __init__(self, driver):
        super(SecurityGroupRuleDeleteEndPoint, self).__init__(driver)

    def _execute(self, ctxt, payload):
        session = db.get_session()
        groups = session.query(securitygroups_db.SecurityGroup).all()
        ids = [g['id'] for g in groups]
        self.update_security_group(ctxt, *ids)
