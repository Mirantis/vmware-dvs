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

from neutron import context
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.agent.common import config
from neutron.common import config as common_config
from neutron.common import utils as q_utils
from neutron.common import topics
from neutron.i18n import _LE
from neutron.i18n import _LI

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'mech_vmware_dvs.config')


class DVSPluginApi(agent_rpc.PluginApi):
    pass


class DVSNeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    def __init__(self, polling_interval=None, quitting_rpc_timeout=None):
        """Constructor.

        :param polling_interval: interval (secs) to poll.
        """
        super(DVSNeutronAgent, self).__init__()

        self.polling_interval = polling_interval

        self.setup_rpc()

        self.iter_num = 0
        self.run_daemon_loop = True

        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.quitting_rpc_timeout = quitting_rpc_timeout

    def setup_rpc(self):
        self.plugin_rpc = DVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.topic = topics.AGENT

        consumers = [
            [topics.PORT, topics.CREATE],
            [topics.PORT, topics.UPDATE],
            [topics.PORT, topics.DELETE],
            [topics.NETWORK, topics.CREATE],
            [topics.NETWORK, topics.UPDATE],
            [topics.NETWORK, topics.DELETE],
            [topics.SECURITY_GROUP, topics.UPDATE],
        ]

        self.context = context.get_admin_context_without_session()

        self.endpoints = [self]

        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(
            self.context,
            self.sg_plugin_rpc,
            defer_refresh_firewall=False)

    def daemon_loop(self):
        while self.run_daemon_loop:
            start = time.time()
            #TODO: write body of loop
            self.loop_count_and_wait(start)

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


def create_agent_config_map(config):
    kwargs = dict(
        polling_interval=config.AGENT.polling_interval,
        quitting_rpc_timeout=config.AGENT.quitting_rpc_timeout
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
