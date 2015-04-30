..

================================
Installation
================================

Usage of the driver is determined by manual creation of DVS switches on VMware vSphere infrastructure first.

Neutron configuration
=====================

[ml2_type_vlan]
network_vlan_ranges = physnet1:<VLAN_RANGE>

[ml2_vmware]
vsphere_hostname=<vCenter_ip_address>
vsphere_login=<vCenter_admin_user>
vsphere_password=<vCenter_admin_password>

# The mappings between physical networks and dvs, i.e.
network_maps = physnet1:dvSwitch1,physnet2:dvSwitch2,...

