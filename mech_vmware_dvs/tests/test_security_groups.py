#!/usr/bin/evn python

import sys
import pprint

from oslo.vmware import api as vmware_api
from oslo.vmware import vim_util


vcenter_host = '69.50.224.75'
vcenter_login = 'root'
vcenter_password = 'Rohdee6w'
vcenter_retry_count = 4
vcenter_retry_interval = 2


def main():
    vcenter = _make_connect()
    dvs = _lookup_dvs(vcenter, 'dvSwitch')
    port = _lookup_dvs_port(vcenter, dvs, '1024')

    spec_factory = vcenter.vim.client.factory

    port_spec = spec_factory.create('ns0:DVPortConfigSpec')
    port_spec.operation = 'edit'
    port_spec.key = port.key
    port_spec.configVersion = port.config.configVersion
    port_spec.setting = port_setting = spec_factory.create('ns0:DVPortSetting')

    port_setting.filterPolicy = filter_policy = spec_factory.create(
        'ns0:DvsFilterPolicy')

    filter_policy.filterConfig.append(spec_factory.create(
        'ns0:DvsTrafficFilterConfig'))
    filter_policy.inherited = False

    filter_config = filter_policy.filterConfig[0]
    filter_config.agentName = "custom-dvs-firewall-agent"
    filter_config.inherited = False
    filter_config.trafficRuleset = traffic_ruleset = spec_factory.create(
        'ns0:DvsTrafficRuleset')

    traffic_ruleset.enabled = True
    traffic_ruleset.rules.append(spec_factory.create('ns0:DvsTrafficRule'))

    rule = traffic_ruleset.rules[0]
    rule.description = "Port rule 0"
    rule.sequence = 10
    rule.direction = "incomingPackets"
    rule.action = spec_factory.create('ns0:DvsDropNetworkRuleAction')
    rule.qualifier.append(spec_factory.create('ns0:DvsIpNetworkRuleQualifier'))

    match = rule.qualifier[0]
    match.protocol = proto = spec_factory.create('ns0:IntExpression')

    proto.value = 6
    proto.negate = False

    match.destinationIpPort = port = spec_factory.create('ns0:DvsSingleIpPort')

    port.portNumber = 50001
    port.negate = False

    task = vcenter.invoke_api(
        vcenter.vim,
        'ReconfigureDVPort_Task',
        dvs, port=[port_spec]
    )
    result = vcenter.wait_for_task(task)
    pprint.pprint(result)


def _make_connect():
    return vmware_api.VMwareAPISession(
        vcenter_host,
        vcenter_login,
        vcenter_password,
        vcenter_retry_count,
        vcenter_retry_interval)


def _lookup_dvs(vcenter, name):
    network_folder = _lookup_net_folder(vcenter)
    networks = vcenter.invoke_api(
        vim_util, 'get_object_property', vcenter.vim,
        network_folder, 'childEntity').ManagedObjectReference

    for dvs in _filter_objects_by_type(
            networks, 'VmwareDistributedVirtualSwitch'):
        dvs_name = vcenter.invoke_api(
            vim_util, 'get_object_property',
            vcenter.vim, dvs, 'name')
        if dvs_name != name:
            continue

        break
    else:
        raise RuntimeError('DVS name=="{}" not found'.format(name))
    return dvs


def _lookup_dvs_port(vcenter, dvs, port_key):
    spec_factory = vcenter.vim.client.factory

    criteria = spec_factory.create(
        'ns0:DistributedVirtualSwitchPortCriteria')
    criteria.portKey = port_key

    try:
        port = vcenter.invoke_api(
            vcenter.vim, 'FetchDVPorts', dvs, criteria=criteria)[0]
    except IndexError:
        raise RuntimeError('DVS port key=="{}" not found'.format(port_key))
    return port


def _lookup_net_folder(vcenter):
    dc = _lookup_datacenter(vcenter)
    return vcenter.invoke_api(
        vim_util, 'get_object_property', vcenter.vim,
        dc, 'networkFolder')


def _lookup_datacenter(vcenter):
    return vcenter.invoke_api(
        vim_util, 'get_objects', vcenter.vim,
        'Datacenter', 100, ['name']).objects[0].obj


def _filter_objects_by_type(sequence, value):
    return (obj for obj in sequence
            if obj._type == value)


if __name__ == '__main__':
    sys.exit(main())