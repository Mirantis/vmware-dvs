==========
vmware-dvs
==========

Goal
====
There is requests from openstack users to have ability to build hybrid
clouds with KVM and ESXi hypervisors (managed by vCenter; DVS is used for
network connectivity). VM on ESXi and VM on KVM should communicate with each
other. But there is no support for VMWare vSphere controller on neutron side.

Our goal is to fully controll over ESXi hypervisor network (specifically when
vCenter and DVS are used on VMware side) via neutron API.
