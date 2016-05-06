from oslo_config import cfg

from neutron.agent.common import config

DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []
DEFAULT_TUNNEL_TYPES = []

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.IntOpt('quitting_rpc_timeout', default=10,
               help=_("Set new timeout in seconds for new rpc calls after "
                      "agent receives SIGTERM. If value is set to 0, rpc "
                      "timeout won't be changed")),
]

vmware_opts = [
    cfg.FloatOpt(
        'task_poll_interval',
        default=2,
        help=_('The interval of task polling in seconds.')),
    cfg.IntOpt(
        'api_retry_count',
        default=10,
        help=_('number of times an API must be retried upon '
               'session/connection related errors')),
    cfg.IntOpt(
        'connections_pool_size',
        default=100,
        help=_('number of vsphere connections pool '
               'must be higher for intensive operations')),
    cfg.StrOpt('vsphere_login', default='administrator',
               help=_("Vsphere login.")),
    cfg.ListOpt('network_maps',
               default=DEFAULT_BRIDGE_MAPPINGS,
               help=_("List of <physical_network>:<bridge>.")),
    cfg.StrOpt('vsphere_hostname', default='vsphere',
               help=_("Vsphere host name or IP.")),
    cfg.StrOpt('vsphere_password', default='',
               help=_("Vsphere password.")),
]

dvs_opts = [
    cfg.BoolOpt('clean_on_restart',
               default=True,
               help=_("Run DVS cleaning procedure on agent restart.")),
    cfg.BoolOpt('precreate_networks',
               default=True,
               help=_("Precreate networks on DVS")),
]

cfg.CONF.register_opts(dvs_opts, "DVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
cfg.CONF.register_opts(vmware_opts, "ML2_VMWARE")
config.register_agent_state_opts_helper(cfg.CONF)
CONF = cfg.CONF
