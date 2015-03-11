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

import uuid

from oslo_vmware import api
from oslo_vmware import exceptions as vmware_exceptions
from oslo_vmware import vim_util

from neutron.i18n import _LI
from neutron.openstack.common import log
from neutron.plugins.ml2.drivers.mech_vmware_dvs import exceptions

# max ports number that can be created on single DVS
DVS_PORTS_NUMBER = 128
LOG = log.getLogger(__name__)


class DVSController(object):
    """Controls one DVS."""

    def __init__(self, dvs, connection):
        self.connection = connection
        self.dvs_name = dvs

    def create_network(self, network, segment):
        name = self._get_net_name(network)
        vlan_id = segment['segmentation_id']
        try:
            dvs_ref = self._get_dvs()
            pg_spec = self._build_pg_spec(name, vlan_id)
            pg_create_task = self.connection.invoke_api(
                self.connection.vim,
                'CreateDVPortgroup_Task',
                dvs_ref, spec=pg_spec)

            result = self.connection.wait_for_task(pg_create_task)
        except vmware_exceptions.VimException as e:
            raise exceptions.create_from_original_exc(e)
        else:
            pg = result.result
            LOG.info(_LI('Network %(name)s created \n%(pg_ref)s'),
                     {'name': name, 'pg_ref': pg})

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
        except exceptions.PortGroupNotFoundException:
            LOG.debug('Network %s not present in vcenter.' % name)
        except vmware_exceptions.VimException as e:
            raise exceptions.create_from_original_exc(e)

    def _build_pg_spec(self, name, vlan_tag):
        client_factory = self.connection.vim.client.factory
        pg_spec = client_factory.create('ns0:DVPortgroupConfigSpec')
        pg_spec.name = name
        pg_spec.numPorts = DVS_PORTS_NUMBER
        pg_spec.type = 'ephemeral'
        pg_spec.description = 'Managed By Neutron'
        config = client_factory.create('ns0:VMwareDVSPortSetting')
        # Create the spec for the vlan tag
        spec_ns = 'ns0:VmwareDistributedVirtualSwitchVlanIdSpec'
        vlan_spec = client_factory.create(spec_ns)
        vlan_spec.vlanId = vlan_tag
        vlan_spec.inherited = '0'
        config.vlan = vlan_spec
        pg_spec.defaultPortConfig = config
        return pg_spec

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
            raise exceptions.DVSNotFoundException(
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
            raise exceptions.PortGroupNotFoundException(pg_name=pg_name)

    @staticmethod
    def _get_net_name(network):
        return 'os-' + uuid.UUID('{%s}' % network['id']).get_hex()

    @staticmethod
    def _get_object_by_type(results, type_value):
        """Get object by type.

        Get the desired object from the given objects
        result by the given type.
        """
        return [obj for obj in results
                if obj._type == type_value]


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
