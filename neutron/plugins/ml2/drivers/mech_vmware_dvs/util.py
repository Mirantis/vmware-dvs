# Copyright 2010-2011 OpenStack Foundation
# Copyright 2012-2013 IBM Corp.
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

from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util

from neutron.i18n import _LI
from neutron.openstack.common import log
from neutron.plugins.ml2.drivers.mech_vmware_dvs import exceptions

# max ports number that can be created on single DVS
DVS_PORTS_NUMBER = 128
DVS_PORTGROUP_NAME_MAXLEN = 80
LOG = log.getLogger(__name__)


class DVSController(object):
    """Controls one DVS."""

    def __init__(self, dvs, connection):
        self.connection = connection
        self.dvs_name = dvs

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
            pg_config_info = self._get_pg_config_info(pg_ref)
            if not pg_config_info.defaultPortConfig.blocked.value == blocked:
                # we upgrade only defaultPortConfig, because it is inherited
                # by all ports in PortGroup, unless they are explicite
                # overwritten on specific port.
                pg_spec = self._build_pg_update_spec(
                    pg_config_info.configVersion,
                    blocked)
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

    def is_dvs_network(self, network):
        name = self._get_net_name(network)
        try:
            self._get_pg_by_name(name)
        except exceptions.PortGroupNotFound:
            return False
        return True

    def _build_pg_create_spec(self, name, vlan_tag, blocked):
        builder = SpecBuilder(self.connection)
        port = builder.port_config()
        port.vlan = builder.vlan(vlan_tag)
        port.blocked = builder.blocked(blocked)
        pg = builder.pg_config(port)
        pg.name = name
        pg.numPorts = DVS_PORTS_NUMBER
        pg.type = 'ephemeral'
        pg.description = 'Managed By Neutron'
        return pg

    def _build_pg_update_spec(self, config_version, blocked):
        builder = SpecBuilder(self.connection)
        port = builder.port_config()
        port.blocked = builder.blocked(blocked)
        pg = builder.pg_config(port)
        pg.configVersion = config_version
        return pg

    def _get_datacenter(self):
        """Get the datacenter reference."""
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
                return dvs
        else:
            raise exceptions.DVSNotFound(
                dvs_name=self.dvs_name)

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
        else:
            raise exceptions.PortGroupNotFound(pg_name=pg_name)

    def _get_pg_config_info(self, pg):
        """pg - ManagedObjectReference of Port Group"""
        return self.connection.invoke_api(
            vim_util, 'get_object_property',
            self.connection.vim, pg, 'config')

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

        if not re.match('^[\w-]+$', name):
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


class SpecBuilder(object):
    """Builds specs for vSphere API calls"""

    def __init__(self, connection):
        self.factory = connection.vim.client.factory

    def pg_config(self, default_port_config):
        spec = self.factory.create('ns0:DVPortgroupConfigSpec')
        spec.defaultPortConfig = default_port_config
        return spec

    def port_config(self):
        return self.factory.create('ns0:VMwareDVSPortSetting')

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
