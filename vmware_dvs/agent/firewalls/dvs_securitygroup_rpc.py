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

from threading import Timer
from oslo_log import log as logging

from neutron.agent import firewall
from neutron.agent import securitygroups_rpc
from neutron.i18n import _LI, _LW

from vmware_dvs.utils.rpc_translator import update_rules

LOG = logging.getLogger(__name__)

sg_cfg = securitygroups_rpc.cfg.CONF.SECURITYGROUP


class DVSSecurityGroupRpc(securitygroups_rpc.SecurityGroupAgentRpc):

    def __init__(self, context, plugin_rpc,
                 defer_refresh_firewall=False):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.init_firewall(defer_refresh_firewall)

    def init_firewall(self, defer_refresh_firewall=False):
        firewall_driver = sg_cfg.firewall_driver or 'noop'
        LOG.debug("Init firewall settings (driver=%s)", firewall_driver)
        if not securitygroups_rpc._is_valid_driver_combination():
            LOG.warn(_LW("Driver configuration doesn't match "
                         "with enable_security_group"))
        firewall_class = firewall.load_firewall_driver_class(firewall_driver)
        self.firewall = firewall_class()
        # The following flag will be set to true if port filter must not be
        # applied as soon as a rule or membership notification is received
        self.defer_refresh_firewall = defer_refresh_firewall
        # Stores devices for which firewall should be refreshed when
        # deferred refresh is enabled.
        self.devices_to_refilter = set()
        # Flag raised when a global refresh is needed
        self.global_refresh_firewall = False
        self._use_enhanced_rpc = None
        self._dev_to_update = set()

    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Preparing filters for devices %s"), device_ids)

        if self.use_enhanced_rpc:
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, list(device_ids))
            devices = update_rules(devices_info)
        else:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, list(device_ids))
        self.firewall.prepare_port_filter(devices.values())

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Remove device filter for %r"), device_ids)
        self.firewall.remove_port_filter(device_ids)

    def _port_refresh(self):
        device_ids = self._dev_to_update
        self._dev_to_update = self._dev_to_update - device_ids
        if not device_ids:
            return
        if self.use_enhanced_rpc:
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, device_ids)
            devices = update_rules(devices_info)
        else:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, device_ids)
        self.firewall.update_port_filter(devices.values())

    def refresh_firewall(self, device_ids=None):
        LOG.info(_LI("Refresh firewall rules"))
        self._dev_to_update |= device_ids
        Timer(2, self._port_refresh).start()
