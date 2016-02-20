============
Installation
============

Installation of vmware-dvs driver
=================================
vmware-dvs driver is installed as a plugin for neutron.
You can just install it via pip:

.. code:: bash

  $ pip install git+git://github.com/Mirantis/vmware-dvs.git@liberty


VSphere configuration
=====================

Usage of the driver is determined by manual creation of DVS switches on
VMware vSphere infrastructure first. Each cluster must have independent
set of DVS switches.

Neutron configuration
=====================

To enable vmware-dvs driver you have to update neutron configuration like this:

.. code:: ini

  # /etc/neutron/plugins/ml2/ml2_conf.ini

  [ml2]
  mechanism_drivers = openvswitch,vmware_dvs

.. code:: ini

  # /etc/neutron/neutron.conf

  [DEFAULT]
  nova_admin_tenant_name = <nova admin tenant name>
  nova_admin_username = <nova admin user name>
  nova_admin_password = <nova admin password>
  nova_admin_tenant_id = <nova admin tenant_id>

On Compute node that proxies requests to vCenter apply
nova patch: https://github.com/Mirantis/vmware-dvs/blob/master/nova.patch
and restart nova-compute

On Controller update python package "suds" to this version: https://github.com/yunesj/suds commit 8dc6ae334272930a548c45665117ecded54c5f60

For further configuration options that needs to be set look into:
/etc/neutron/plugins/ml2/ml2_conf.ini please read etc/ml2_conf_vmware_dvs.ini
in this repository.


Agents configuration
====================

For each cluster create /etc/neutron/plugins/ml2/ml2_conf_ClusterName.ini
Create section

[DEFAULT]
host=<HostName>

HostName must be the same as host name at default section of nova-compute.conf for cluster

update 

[ml2_vmware]
vsphere_login=<login>
network_maps=<physnet_name>:<DVS_name>
vsphere_hostname=<ip or name of vSphere server>
vsphere_password=<password>
