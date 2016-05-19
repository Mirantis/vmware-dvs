# Copyright 2016 Mirantis, Inc.
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

import copy


def update_rules(enh_rpc):
    sg_members = enh_rpc['sg_member_ips']
    devices = enh_rpc['devices']
    sg = enh_rpc['security_groups']
    ret = copy.copy(devices)
    for device in devices:
        sg_dev = devices[device]['security_groups']
        my_ip = devices[device]['fixed_ips']
        for sg in sg_dev:
            sg_rules = enh_rpc['security_groups'][sg]
            for sgrule in sg_rules:
                if 'remote_group_id' in sgrule:
                    ret[device]['security_group_rules'].extend(
                        build_rules_from_sg(sgrule, sg_members, sg, my_ip))
                else:
                    ret[device]['security_group_rules'].append(sgrule)
    return ret


def build_rules_from_sg(rule, sg_members, sg, my_ip):
    rules = []
    for ips in sg_members[rule['remote_group_id']][rule['ethertype']]:
        if ips not in my_ip:
            r_builder = copy.copy(rule)
            if rule['direction'] == 'ingress':
                r_builder[u'source_ip_prefix'] = ips + '/32'
            else:
                r_builder[u'dest_ip_prefix'] = ips + '/32'
            rules.append(r_builder)
    return rules
