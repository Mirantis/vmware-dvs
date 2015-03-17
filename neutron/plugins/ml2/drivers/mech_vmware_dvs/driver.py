# Copyright 2010-2011 OpenStack Foundation
# Copyright 2012-2013 IBM Corp.
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
from neutron.i18n import _LI
from neutron.openstack.common import log
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers.mech_vmware_dvs import config
from neutron.plugins.ml2.drivers.mech_vmware_dvs import exceptions
from neutron.plugins.ml2.drivers.mech_vmware_dvs import util


CONF = config.CONF
LOG = log.getLogger(__name__)


class VMwareDVSMechanismDriver(driver_api.MechanismDriver):
    """Ml2 Mechanism driver for vmware dvs."""

    def initialize(self):
        self.network_map = util.create_network_map_from_config(CONF.ml2_vmware)

    def create_network_precommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context)
        except exceptions.NoDVSForPhysicalNetwork as e:
            LOG.info(_LI('Network %(id)s not created. Reason: %(reason)s') % {
                'id': context.current['id'],
                'reason': e.message})
        else:
            dvs.create_network(context.current, context.network_segments[0])

    def update_network_precommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context)
        except exceptions.NoDVSForPhysicalNetwork as e:
            LOG.info(_LI('Network %(id)s not updated. Reason: %(reason)s') % {
                'id': context.current['id'],
                'reason': e.message})
        else:
            dvs.update_network(context.current)

    def delete_network_postcommit(self, context):
        try:
            dvs = self._lookup_dvs_for_context(context)
        except exceptions.NoDVSForPhysicalNetwork as e:
            LOG.info(_LI('Network %(id)s not deleted. Reason: %(reason)s') % {
                'id': context.current['id'],
                'reason': e.message})
        else:
            dvs.delete_network(context.current)

    def _lookup_dvs_for_context(self, context):
        segment = context.network_segments[0]
        if segment['network_type'] == constants.TYPE_VLAN:
            physical_network = segment['physical_network']
            try:
                return self.network_map[physical_network]
            except KeyError:
                LOG.debug('No dvs mapped for physical '
                          'network: %s' % physical_network)
                raise exceptions.NoDVSForPhysicalNetwork(
                    physical_network=physical_network)
        else:
            raise exceptions.NotSupportedNetworkType(
                network_type=segment['network_type'])
