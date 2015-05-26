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


from oslo.config import cfg

vmware_opts = [
    cfg.StrOpt(
        'vsphere_hostname',
        default='localhost',
        help=_('Hostname or IP address of vmware vcenter server.')),
    cfg.StrOpt(
        'vsphere_login',
        default='administrator',
        help=_('The login of vcenter server.')),
    cfg.StrOpt(
        'vsphere_password',
        default='password',
        secret=True,
        help=_('The password of vcenter server.')),
    cfg.FloatOpt(
        'task_poll_interval',
        default=2,
        help=_('The interval of task polling in seconds.')),
    cfg.IntOpt(
        'api_retry_count',
        default=10,
        help=_('number of times an API must be retried upon '
               'session/connection related errors')),
    cfg.ListOpt(
        'network_maps',
        default=[],
        help=_('The mappings between physical networks and dvs'))
]

cfg.CONF.register_opts(vmware_opts, group='ml2_vmware')
CONF = cfg.CONF
