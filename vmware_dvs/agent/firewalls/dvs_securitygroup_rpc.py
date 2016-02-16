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
from oslo_log import log as logging

from neutron.agent import securitygroups_rpc

LOG = logging.getLogger(__name__)


class DVSSecurityGroupRpc(securitygroups_rpc.SecurityGroupAgentRpc):

    def _update_security_group_info(self, security_groups,
                                    security_group_member_ips):
        if security_group_member_ips and security_groups:
            self.firewall.update_security_group_rules_and_members(
                security_groups, security_group_member_ips)
            LOG.debug("Update security group members and security group rules "
                      "information")
        else:
            for sg_id, sg_rules in security_groups.items():
                self.firewall.update_security_group_rules(sg_id, sg_rules)
            LOG.debug("Update security group information")
            for remote_sg_id, member_ips in security_group_member_ips.items():
                self.firewall.update_security_group_members(
                    remote_sg_id, member_ips)
                LOG.debug("Update security group members information")
