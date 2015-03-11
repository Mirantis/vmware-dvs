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

from neutron.common import exceptions


class VMWareDVSException(exceptions.NeutronException):
    """Base of all exceptions throwed by mech_vmware_dvs driver"""
    message = _('VMWare DVS exception occurred.')


class NotSupportedNetworkTypeException(exceptions.NeutronException):
    message = _("VMWare DVS driver don't support %s(network_type) network")


class ResourceNotFondException(VMWareDVSException):
    message = _('Resource not found')


class DVSNotFoundException(ResourceNotFondException):
    message = _('Distributed Virtual Switch %(dvs_name)s not found')


class PortGroupNotFoundException(ResourceNotFondException):
    message = _('Port Group %(pg_name)s not found')


class NoDVSForPhysicalNetworkException(VMWareDVSException):
    message = _('No dvs mapped for physical network: %(physical_network)s')


def create_from_original_exc(original_exception):
    exc_type = type(original_exception)
    exc_msg = original_exception.message
    message = _('Original Exception: <%(type)s: %(message)s>') % {
        'type': exc_type,
        'message': exc_msg}
    return VMWareDVSException(message=message)
