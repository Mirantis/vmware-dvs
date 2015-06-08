# Copyright 2015 Mirantis, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
import abc

import six
from oslo_concurrency import lockutils
from oslo_log import log
from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util
from neutron.i18n import _LI

from mech_vmware_dvs import exceptions

LOG = log.getLogger(__name__)

DVS_PORTGROUP_NAME_MAXLEN = 80
VM_NETWORK_DEVICE_TYPES = [
    'VirtualE1000', 'VirtualE1000e', 'VirtualPCNet32',
    'VirtualSriovEthernetCard', 'VirtualVmxnet']


class DVSController(object):
    """Controls one DVS."""

    def __init__(self, dvs, connection):
        self.connection = connection
        self.dvs_name = dvs
        self.dvs_ref = None

    def create_network(self, network, segment):
        name = self._get_net_name(network)
        blocked = not network['admin_state_up']

        try:
            dvs_ref = self._get_dvs()
            pg_spec = self._build_pg_create_spec(
                name,
                segment['segmentation_id'],
                blocked)
            pg_create_task = self.connection.invoke_api(
                self.connection.vim,
                'CreateDVPortgroup_Task',
                dvs_ref, spec=pg_spec)

            result = self.connection.wait_for_task(pg_create_task)
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)
        else:
            pg = result.result
            LOG.info(_LI('Network %(name)s created \n%(pg_ref)s'),
                     {'name': name, 'pg_ref': pg})

    def update_network(self, network):
        name = self._get_net_name(network)
        blocked = not network['admin_state_up']
        try:
            pg_ref = self._get_pg_by_name(name)
            pg_config_info = self._get_config_by_ref(pg_ref)
            if not pg_config_info.defaultPortConfig.blocked.value == blocked:
                # we upgrade only defaultPortConfig, because it is inherited
                # by all ports in PortGroup, unless they are explicite
                # overwritten on specific port.
                pg_spec = self._build_pg_update_spec(
                    pg_config_info.configVersion,
                    blocked=blocked)
                pg_update_task = self.connection.invoke_api(
                    self.connection.vim,
                    'ReconfigureDVPortgroup_Task',
                    pg_ref, spec=pg_spec)

                self.connection.wait_for_task(pg_update_task)
                LOG.info(_LI('Network %(name)s updated'), {'name': name})
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    def delete_network(self, network):
        name = self._get_net_name(network)
        try:
            pg_ref = self._get_pg_by_name(name)
            pg_delete_task = self.connection.invoke_api(
                self.connection.vim,
                'Destroy_Task',
                pg_ref)
            self.connection.wait_for_task(pg_delete_task)
            LOG.info(_LI('Network %(name)s deleted.') % {'name': name})
        except exceptions.PortGroupNotFound:
            LOG.debug('Network %s not present in vcenter.' % name)
        except vmware_exceptions.VimException as e:
            raise exceptions.wrap_wmvare_vim_exception(e)

    @lockutils.synchronized('vmware_dvs_bind_port', external=True)
    def switch_port_blocked_state(self, port, state=None):
        if state is None:
            state = not port['admin_state_up']
        dvport = self._get_dvport(port)
        port_settings = dvport.config.setting

        if port_settings.blocked.value != state:
            builder = SpecBuilder(self.connection.vim.client.factory)

            port_settings = builder.port_setting()
            port_settings.blocked = builder.blocked(state)

            update_spec = builder.port_config_spec(
                dvport.config.configVersion, port_settings)
            update_spec.operation = 'edit'
            update_spec.key = dvport.key
            update_spec = [update_spec]
            update_task = self.connection.invoke_api(
                self.connection.vim, 'ReconfigureDVPort_Task',
                self._get_dvs(), port=update_spec)
            self.connection.wait_for_task(update_task)

    def _get_dvport(self, port):
        try:
            vm_uuid = port['device_id']
        except KeyError:
            raise exceptions.VMNotFound

        dvs_ref = self._get_dvs()
        vm_ref = self._get_vm_by_uuid(vm_uuid)
        port = self._get_port_by_neutron_uuid(dvs_ref, vm_ref, port['id'])
        return port

    def _build_pg_create_spec(self, name, vlan_tag, blocked):
        builder = SpecBuilder(self.connection.vim.client.factory)
        port = builder.port_setting()
        port.vlan = builder.vlan(vlan_tag)
        port.blocked = builder.blocked(blocked)
        pg = builder.pg_config(port)
        pg.name = name
        pg.numPorts = 0

        # Equivalent of vCenter static binding type.
        pg.type = 'earlyBinding'
        pg.description = 'Managed By Neutron'
        return pg

    def _build_pg_update_spec(self, config_version,
                              blocked=None,
                              ports_number=None):
        builder = SpecBuilder(self.connection.vim.client.factory)
        port = builder.port_setting()
        if blocked is not None:
            port.blocked = builder.blocked(blocked)
        pg = builder.pg_config(port)
        if ports_number:
            pg.numPorts = ports_number
        pg.configVersion = config_version
        return pg

    def _get_datacenter(self):
        """Get the datacenter reference."""
        # FIXME(dobgun): lookup datacenter by name(add it into config)
        results = self.connection.invoke_api(
            vim_util, 'get_objects', self.connection.vim,
            'Datacenter', 100, ['name'])
        return results.objects[0].obj

    def _get_network_folder(self):
        """Get the network folder from datacenter."""
        dc_ref = self._get_datacenter()
        results = self.connection.invoke_api(
            vim_util, 'get_object_property', self.connection.vim,
            dc_ref, 'networkFolder')
        return results

    def _get_dvs(self):
        """Get the dvs by name"""
        net_folder = self._get_network_folder()
        results = self.connection.invoke_api(
            vim_util, 'get_object_property', self.connection.vim,
            net_folder, 'childEntity')
        networks = results.ManagedObjectReference
        dvswitches = self._get_object_by_type(networks,
                                              'VmwareDistributedVirtualSwitch')
        for dvs in dvswitches:
            name = self.connection.invoke_api(
                vim_util, 'get_object_property',
                self.connection.vim, dvs, 'name')
            if name == self.dvs_name:
                dvs_ref = dvs
                break
        else:
            raise exceptions.DVSNotFound(dvs_name=self.dvs_name)
        return dvs_ref

    def _get_pg_by_name(self, pg_name):
        """Get the dpg ref by name"""
        dc_ref = self._get_datacenter()
        net_list = self.connection.invoke_api(
            vim_util, 'get_object_property', self.connection.vim,
            dc_ref, 'network').ManagedObjectReference
        type_value = 'DistributedVirtualPortgroup'
        pg_list = self._get_object_by_type(net_list, type_value)
        for pg in pg_list:
            name = self.connection.invoke_api(
                vim_util, 'get_object_property',
                self.connection.vim, pg, 'name')
            if pg_name == name:
                return pg
        raise exceptions.PortGroupNotFound(pg_name=pg_name)

    def _get_port_by_neutron_uuid(self, dvs_ref, vm_ref, port_uuid):
        port_not_found = exceptions.PortNotFound(
            id='neutron-port-uuid:' + port_uuid)

        vm_config = self._get_config_by_ref(vm_ref)

        iface_option_mask = r'^nvp\.iface-id\.(\d+)$'
        for opt in vm_config.extraConfig:
            match = re.match(iface_option_mask, opt.key)
            if not match:
                continue
            if opt.value != port_uuid:
                continue
            port_idx = match.group(1)
            port_idx = int(port_idx)
            break
        else:
            raise port_not_found

        founded_device = None
        iface_idx = -1
        for device in vm_config.hardware.device:
            if device.__class__.__name__ not in VM_NETWORK_DEVICE_TYPES:
                continue
            iface_idx += 1
            if port_idx != iface_idx:
                continue
            founded_device = device
            break

        if not founded_device:
            raise port_not_found

        port_connection = founded_device.backing.port
        if port_connection.switchUuid != self.connection.invoke_api(
                vim_util, 'get_object_property', self.connection.vim,
                dvs_ref, 'uuid'):
            raise port_not_found

        builder = SpecBuilder(self.connection.vim.client.factory)
        lookup_criteria = builder.port_lookup_criteria()
        lookup_criteria.portKey = port_connection.portKey
        lookup_criteria.uplinkPort = False

        port = self.connection.invoke_api(
            self.connection.vim, 'FetchDVPorts', dvs_ref,
            criteria=lookup_criteria)

        if len(port) != 1:
            raise port_not_found
        return port[0]

    def _get_vm_by_uuid(self, uuid):
        vm_refs = self.connection.invoke_api(
            self.connection.vim, 'FindAllByUuid',
            self.connection.vim.service_content.searchIndex,
            uuid=uuid, vmSearch=True, instanceUuid=True)

        if len(vm_refs) != 1:
            raise exceptions.VMNotFound
        return vm_refs[0]

    def _get_config_by_ref(self, ref):
        """pg - ManagedObjectReference of Port Group"""
        return self.connection.invoke_api(
            vim_util, 'get_object_property',
            self.connection.vim, ref, 'config')

    @staticmethod
    def _get_net_name(network):
        # TODO(dbogun): check network['bridge'] generation algorithm our
        # must match it
        suffix = network['id']

        name = network.get('name')
        if not name:
            return suffix

        suffix = '-' + suffix
        if DVS_PORTGROUP_NAME_MAXLEN < len(name) + len(suffix):
            raise exceptions.InvalidNetworkName(
                name=name,
                reason=_('name length %(length)s, while allowed length is '
                         '%(max_length)d') % {
                    'length': len(name),
                    'max_length': DVS_PORTGROUP_NAME_MAXLEN - len(suffix)})

        if not re.match(r'^[\w-]+$', name):
            raise exceptions.InvalidNetworkName(
                name=name,
                reason=_('name contains illegal symbols. Only alphanumeric, '
                         'underscore and hyphen are allowed.'))

        return name + suffix

    @staticmethod
    def _get_object_by_type(results, type_value):
        """Get object by type.

        Get the desired object from the given objects
        result by the given type.
        """
        return [obj for obj in results
                if obj._type == type_value]

    def _get_ports_for_pg(self, pg_name):
        pg = self._get_pg_by_name(pg_name)
        return self.connection.invoke_api(
            vim_util, 'get_object_property',
            self.connection.vim, pg, 'portKeys')[0]

    @lockutils.synchronized('vmware_dvs_bind_port', external=True)
    def update_port_rules(self, ports):
        builder = SpecBuilder(self.connection.vim.client.factory)
        port_config_list = []
        for port in ports:
            port_key = port['binding:vif_details']['dvs_port_key']
            port_info = self._get_port_info(port_key)
            port_config = builder.port_config(
                str(port_key),
                port['security_group_rules']
            )
            port_config.configVersion = port_info['config']['configVersion']
            port_config_list.append(port_config)
        dvs = self._get_dvs()
        task = self.connection.invoke_api(
            self.connection.vim,
            'ReconfigureDVPort_Task',
            dvs, port=port_config_list
        )
        return self.connection.wait_for_task(task)

    def get_unbound_port_key(self, network, bound_ports):
        """
        returns first empty port in portgroup
        If there is now empty port, than we double ports number in portgroup
        """
        net_name = self._get_net_name(network)
        pg = self._get_pg_by_name(net_name)
        try:
            return self._lookup_unbound_port(pg, bound_ports)
        except exceptions.UnboundPortNotFound:
            self._increase_ports_on_portgroup(pg)
            return self._lookup_unbound_port(pg, bound_ports)

    def _lookup_unbound_port(self, port_group, bound_ports):
        builder = SpecBuilder(self.connection.vim.client.factory)
        criteria = builder.port_criteria(port_group_key=port_group.value)
        dvs = self._get_dvs()

        ports = self.connection.invoke_api(
            self.connection.vim,
            'FetchDVPorts',
            dvs, criteria=criteria)
        for port in ports:
            if port.key not in bound_ports:
                return port.key
        raise exceptions.UnboundPortNotFound()

    def _increase_ports_on_portgroup(self, port_group):
        pg_info = self._get_config_by_ref(port_group)
        ports_number = pg_info.numPorts * 2 if pg_info.numPorts else 1
        pg_spec = self._build_pg_update_spec(
            pg_info.configVersion, ports_number=ports_number)
        pg_update_task = self.connection.invoke_api(
            self.connection.vim,
            'ReconfigureDVPortgroup_Task',
            port_group, spec=pg_spec)
        self.connection.wait_for_task(pg_update_task)

    def _get_port_info(self, port_key):
        """pg - ManagedObjectReference of Port Group"""
        builder = SpecBuilder(self.connection.vim.client.factory)
        criteria = builder.port_criteria(port_key=port_key)
        dvs = self._get_dvs()
        return self.connection.invoke_api(
            self.connection.vim,
            'FetchDVPorts',
            dvs, criteria=criteria)[0]


class SpecBuilder(object):
    """Builds specs for vSphere API calls"""

    def __init__(self, spec_factory):
        self.factory = spec_factory

    def pg_config(self, default_port_config):
        spec = self.factory.create('ns0:DVPortgroupConfigSpec')
        spec.defaultPortConfig = default_port_config
        policy = self.factory.create('ns0:DVPortgroupPolicy')
        policy.blockOverrideAllowed = '1'
        policy.livePortMovingAllowed = '0'
        policy.portConfigResetAtDisconnect = '1'
        policy.shapingOverrideAllowed = '0'
        policy.trafficFilterOverrideAllowed = '1'
        policy.vendorConfigOverrideAllowed = '0'
        spec.policy = policy
        return spec

    def port_config_spec(self, version, config):
        spec = self.factory.create('ns0:DVPortConfigSpec')
        spec.configVersion = version
        spec.setting = config
        return spec

    def port_lookup_criteria(self):
        return self.factory.create('ns0:DistributedVirtualSwitchPortCriteria')

    def port_setting(self):
        return self.factory.create('ns0:VMwareDVSPortSetting')

    def port_config(self, port_key, sg_rules):
        rules = []
        for i, rule_info in enumerate(sg_rules):
            if 'ip_set' in rule_info:
                for ip in rule_info['ip_set']:
                    rule_info['direction'] = 'ingress'
                    rules.append(self._create_rule(rule_info, i * 10, ip))
                    rule_info['direction'] = 'egress'
                    rules.append(self._create_rule(rule_info, i * 10 + 5, ip))
            else:
                rules.append(self._create_rule(rule_info, i * 10))

        traffic_ruleset = self.factory.create('ns0:DvsTrafficRuleset')
        traffic_ruleset.enabled = '1'
        traffic_ruleset.rules = rules
        filter_config = self.factory.create('ns0:DvsTrafficFilterConfig')
        filter_config.agentName = "dvfilter-generic-vmware"
        filter_config.inherited = '0'
        filter_config.trafficRuleset = traffic_ruleset
        filter_policy = self.factory.create('ns0:DvsFilterPolicy')
        filter_policy.filterConfig = [filter_config]
        filter_policy.inherited = '0'
        setting = self.factory.create('ns0:VMwareDVSPortSetting')
        setting.filterPolicy = filter_policy

        spec = self.factory.create('ns0:DVPortConfigSpec')
        spec.operation = 'edit'
        spec.setting = setting
        spec.key = port_key
        return spec

    def _create_rule(self, rule_info, sequence, ip=None):
        rule_params = {
            'spec_factory': self.factory,
            'ethertype': rule_info['ethertype'],
            'protocol': rule_info.get('protocol'),
            'sequence': sequence
        }
        if rule_info['direction'] == 'ingress':
            rule = IngressRule(**rule_params)
            rule.source_port_range(
                rule_info.get('source_port_range_min'),
                rule_info.get('source_port_range_max')
            )
            rule.cidr(rule_info.get('source_ip_prefix'))

        else:
            rule = EgressRule(**rule_params)
            rule.cidr(rule_info.get('dest_ip_prefix'))
        rule.port_range(rule_info.get('port_range_min'),
                        rule_info.get('port_range_max'))
        rule.cidr(ip)
        return rule.build()

    def port_criteria(self, port_key=None, port_group_key=None):
        criteria = self.factory.create(
            'ns0:DistributedVirtualSwitchPortCriteria')
        if port_key:
            criteria.portKey = port_key
        if port_group_key:
            criteria.portgroupKey = port_group_key
            criteria.inside = '1'
        return criteria

    def vlan(self, vlan_tag):
        spec_ns = 'ns0:VmwareDistributedVirtualSwitchVlanIdSpec'
        spec = self.factory.create(spec_ns)
        spec.inherited = '0'
        spec.vlanId = vlan_tag
        return spec

    def blocked(self, value):
        """Value should be True or False"""
        spec = self.factory.create('ns0:BoolPolicy')
        if value:
            spec.inherited = '0'
            spec.value = 'true'
        else:
            spec.inherited = '1'
            spec.value = 'false'
        return spec


@six.add_metaclass(abc.ABCMeta)
class TrafficRuleBuilder(object):
    # protocol number according to RFC 1700
    PROTOCOL = {'icmp': 1,
                'tcp': 6,
                'udp': 17}
    direction = None

    def __init__(self, spec_factory, ethertype, protocol, sequence):
        self.factory = spec_factory

        self.rule = self.factory.create('ns0:DvsTrafficRule')
        self.rule.sequence = sequence
        self.rule.action = self.factory.create(
            'ns0:DvsAcceptNetworkRuleAction')
        self.rule.direction = self.direction

        self.ip_qualifier = self.factory.create(
            'ns0:DvsIpNetworkRuleQualifier'
        )
        any_ip = '0.0.0.0/0' if ethertype == 'IPv4' else '::/0'
        self.ip_qualifier.sourceAddress = self._cidr_spec(any_ip)
        self.ip_qualifier.destinationAddress = self._cidr_spec(any_ip)
        self.protocol = protocol
        if protocol:
            int_exp = self.factory.create('ns0:IntExpression')
            int_exp.value = self.PROTOCOL.get(protocol, protocol)
            int_exp.negate = 'false'
            self.ip_qualifier.protocol = int_exp

    def build(self):
        self.rule.qualifier = [self.ip_qualifier]
        return self.rule

    @abc.abstractmethod
    def port_range(self, start, end):
        pass

    @abc.abstractmethod
    def cidr(self, cidr):
        pass

    def _port_range_spec(self, start, end):
        if start == end:
            result = self.factory.create('ns0:DvsSingleIpPort')
            result.portNumber = start
        else:
            result = self.factory.create('ns0:DvsIpPortRange')
            result.startPortNumber = start
            result.endPortNumber = end
        return result

    def _cidr_spec(self, cidr):
        try:
            ip, mask = cidr.split('/')
        except ValueError:
            result = self.factory.create('ns0:SingleIp')
            result.address = cidr
        else:
            result = self.factory.create('ns0:IpRange')
            result.addressPrefix = ip
            result.prefixLength = mask
        return result

    def _has_port(self, min_port):
        if min_port:
            if self.protocol == 'icmp':
                LOG.info(_LI('Vmware dvs driver does not support '
                             '"type" and "code" for ICMP protocol.'))
                return False
            else:
                return True
        else:
            return False


class IngressRule(TrafficRuleBuilder):
    direction = 'incomingPackets'

    def port_range(self, start, end):
        if self._has_port(start):
            self.ip_qualifier.destinationIpPort = self._port_range_spec(start,
                                                                        end)

    def source_port_range(self, start, end):
        if start:
            self.ip_qualifier.sourceIpPort = self._port_range_spec(start, end)

    def cidr(self, cidr):
        if cidr:
            self.ip_qualifier.sourceAddress = self._cidr_spec(cidr)


class EgressRule(TrafficRuleBuilder):

    direction = 'outgoingPackets'

    def port_range(self, start, end):
        if self._has_port(start):
            self.ip_qualifier.sourceIpPort = self._port_range_spec(start, end)

    def dest_port_range(self, start, end):
        if start:
            self.ip_qualifier.sourceIpPort = self._port_range_spec(start, end)

    def cidr(self, cidr):
        if cidr:
            self.ip_qualifier.destinationAddress = self._cidr_spec(cidr)


def create_network_map_from_config(config):
    """Creates physical network to dvs map from config"""
    connection = api.VMwareAPISession(
        config.vsphere_hostname,
        config.vsphere_login,
        config.vsphere_password,
        config.api_retry_count,
        config.task_poll_interval)
    network_map = {}
    for pair in config.network_maps:
        network, dvs = pair.split(':')
        network_map[network] = DVSController(dvs, connection)
    return network_map
