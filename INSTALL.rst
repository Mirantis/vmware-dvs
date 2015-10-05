============
Installation
============

Installation of vmware-dvs driver
=================================
vmware-dvs driver is installed as a plugin for neutron.
You can just install it via pip:

.. code:: bash

  $ pip install git+git://github.com/Mirantis/vmware-dvs.git

If you want version compatible with mos v.6.1 (neutron v2014.2.2).
You have to install vmware-dvs from branch "mos-6.1":

.. code:: bash

  $ pip install git+git://github.com/Mirantis/vmware-dvs.git@mos-6.1

VSphere configuration
=====================

Usage of the driver is determined by manual creation of DVS switches on
VMware vSphere infrastructure first.

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

  notification_driver = messagingv2
  notification_topics = notifications,vmware_dvs

On Compute node that proxies requests to vCenter apply
nova patch: https://github.com/Mirantis/vmware-dvs/blob/master/nova.patch
and restart nova-compute

On Controller update python package "suds" to this version: https://github.com/yunesj/suds commit 8dc6ae334272930a548c45665117ecded54c5f60

For further configuration options that needs to be set look into:
/etc/neutron/plugins/ml2/ml2_conf.ini please read etc/ml2_conf_vmware_dvs.ini
in this repository.
