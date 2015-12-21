# Copyright 2015 Mirantis, Inc.
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


import signal
import sys
import time

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron import context
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.agent.common import config
from neutron.agent.common import polling
from neutron.common import constants as q_const
from neutron.common import config as common_config
from neutron.common import utils as q_utils
from neutron.common import topics
from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.openstack.common import loopingcall

from mech_vmware_dvs import util

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'mech_vmware_dvs.config')
cfg.CONF.import_group('ml2_vmware', 'mech_vmware_dvs.config')


class DVSPluginApi(agent_rpc.PluginApi):
    pass


class DVSNeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    target = oslo_messaging.Target(version='1.2')

    def __init__(self, vsphere_hostname, vsphere_login, vsphere_password,
                 polling_interval, bridge_mappings,
                 quitting_rpc_timeout=None):
        """Constructor.

        :param polling_interval: interval (secs) to poll.
        """
        super(DVSNeutronAgent, self).__init__()
        self.polling_interval = polling_interval
        self.agent_state = {
            'bridge_mappings': bridge_mappings,
            'binary': 'neutron-dvs-agent',
            'host': cfg.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {'vsphere_hostname': vsphere_hostname},
            'agent_type': 'DVS agent',
            'start_flag': True}

        self.setup_rpc()
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)
        self.iter_num = 0
        self.run_daemon_loop = True
        # Security group agent support
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(self.context,
                self.sg_plugin_rpc, defer_refresh_firewall=True)
        self.iter_num = 0
        self.run_daemon_loop = True
        self.fullsync = True
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()
        self.quitting_rpc_timeout = quitting_rpc_timeout
        self.updated_ports = set()
        self.deleted_ports = set()
        self.known_ports = set()
        self.added_ports = set()
        self.network_map = util.create_network_map_from_config(
            cfg.CONF.ml2_vmware)

    def _report_state(self):
        try:
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == q_const.AGENT_REVIVED:
                LOG.info(_LI('Agent has just revived. Do a full sync.'))
                self.fullsync = True
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def setup_rpc(self):
        self.agent_id = 'dvs-agent-%s' % cfg.CONF.host
        self.topic = topics.AGENT
        self.plugin_rpc = DVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)

        consumers = [
            [topics.PORT, topics.CREATE],
            [topics.PORT, topics.UPDATE],
            [topics.PORT, topics.DELETE],
            [topics.NETWORK, topics.CREATE],
            [topics.NETWORK, topics.UPDATE],
            [topics.NETWORK, topics.DELETE],
            [topics.SECURITY_GROUP, topics.UPDATE],
        ]
        self.endpoints = [self]
        self.context = context.get_admin_context_without_session()
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def daemon_loop(self):
        with polling.get_polling_manager() as pm:
            self.rpc_loop(polling_manager=pm)

    def rpc_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.get_polling_manager(
                    minimize_polling=False)
        while self.run_daemon_loop:
            start = time.time()
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0}}
            if self.fullsync:
                LOG.info(_LI("Agent out of sync with plugin!"))
                self.fullsync = False
                polling_manager.force_polling()
            if self._agent_has_updates(polling_manager):
                LOG.debug("Agent rpc_loop - update")
                self.process_ports()
                port_stats['regular']['added'] = len(self.added_ports)
                port_stats['regular']['updated'] = len(self.updated_ports)
                port_stats['regular']['removed'] = len(self.deleted_ports)
                polling_manager.polling_completed()

            self.loop_count_and_wait(start, port_stats)

    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.sg_agent.firewall_refresh_needed() or
                self.updated_ports or self.deleted_ports)

    def loop_count_and_wait(self, start_time, port_stats=None):
        # sleep till end of polling interval
        elapsed = time.time() - start_time
        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d "
                  "completed. Processed ports statistics: "
                  "%(port_stats)s. Elapsed:%(elapsed).3f",
                  {'iter_num': self.iter_num,
                   'port_stats': port_stats,
                   'elapsed': elapsed})
        if elapsed < self.polling_interval:
            time.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
        self.iter_num = self.iter_num + 1

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc, self.sg_plugin_rpc):
            rpc_api.client.timeout = timeout

    def process_ports(self):
        LOG.debug("Process deleted ports")
        self.sg_agent.remove_devices_filter(self.deleted_ports)
        self.known_ports |= self.added_ports
        self.added_ports = self._get_dvs_ports() - self.known_ports
        LOG.info(_LI("Added ports %s"), self.added_ports)
        self.sg_agent.setup_port_filters(self.added_ports, self.updated_ports)

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        self.updated_ports.add(port['id'])
        LOG.debug("port_update message processed for port %s", port['id'])

    def port_delete(self, context, **kwargs):
        port_id = kwargs.get('port_id')
        self.deleted_ports.add(port_id)
        self.known_ports.discard(port_id)
        if port_id in self.added_ports:
            self.added_ports.discard(port_id)
        LOG.debug("port_delete message processed for port %s", port_id)

    def _get_dvs_ports(self):
        ports = set()
        dvs_list = self.network_map.values()
        for dvs in dvs_list:
            ports.update(dvs._get_ports_ids())
        return ports


def create_agent_config_map(config):
    try:
        bridge_mappings = q_utils.parse_mappings(
            config.ml2_vmware.network_maps)
    except ValueError as e:
        raise ValueError(_("Parsing network_maps failed: %s.") % e)

    kwargs = dict(
        bridge_mappings=bridge_mappings,
        polling_interval=config.AGENT.polling_interval,
        quitting_rpc_timeout=config.AGENT.quitting_rpc_timeout,
        vsphere_hostname=config.ml2_vmware.vsphere_hostname,
        vsphere_login=config.ml2_vmware.vsphere_login,
        vsphere_password=config.ml2_vmware.vsphere_password,
    )
    return kwargs


def main():
    config.register_root_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_LE('%s Agent terminated!'), e)
        sys.exit(1)

    try:
        agent = DVSNeutronAgent(**agent_config)
    except RuntimeError as e:
        LOG.error(_LE("%s Agent terminated!"), e)

        sys.exit(1)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()

if __name__ == "__main__":
    main()
