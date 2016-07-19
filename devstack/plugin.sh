#!/bin/bash
#
# devstack/plugin.sh
# Functions to control the configuration and operation of the OVSvApp solution
# Dependencies:
#
# ``functions`` file
# ``DEST`` must be defined
# ``STACK_USER`` must be defined

# ``stack.sh`` calls the entry points in this order:
#
# - install_ovsvapp_dependency
# - install_networking_vsphere
# - run_ovsvapp_alembic_migration
# - pre_configure_ovsvapp
# - add_ovsvapp_config
# - configure_ovsvapp_config
# - setup_ovsvapp_bridges
# - start_ovsvapp_agent
# - configure_ovsvapp_compute_driver
# - cleanup_ovsvapp_bridges

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

source $TOP_DIR/lib/neutron_plugins/ovs_base

# DVSvApp Networking-vSphere DIR.
VMWARE_DVS_NETWORKING_DIR=$DEST/networking-vsphere

# Nova VMwareVCDriver DIR
NOVA_VCDRIVER=$NOVA_DIR/nova/virt/vmwareapi/

# DVSvApp patched vif.py
NOVA_VIF=$OVSVAPP_NETWORKING_DIR/networking_vsphere/nova/virt/vmwareapi/vif.py

# DVSvApp patched vm_util.py
NOVA_VM_UTIL=$OVSVAPP_NETWORKING_DIR/networking_vsphere/nova/virt/vmwareapi/vm_util.py

# OVSvApp VCDriver file path
OVSVAPP_VCDRIVER=$OVSVAPP_NETWORKING_DIR/networking_vsphere/nova/virt/vmwareapi/ovsvapp_vc_driver.py

# OVSvApp VMops file path
OVSVAPP_VMOPS=$OVSVAPP_NETWORKING_DIR/networking_vsphere/nova/virt/vmwareapi/ovsvapp_vmops.py

# Do something dependly on current driver.
function _is_vmware {
    if [[ $OVSVAPP_MODE =~ "vmware_dvs" ]]; then
	res=0
    else
	res=1
    fi
    return $res
}

function _when_vmware {
    if _is_vmware ; then
	$*
    fi
}

function _when_ovsvapp {
    if ! _is_vmware ; then
	$*
    fi
}

# Omit ssl verification.
function _patch_oslo_vmware {
    if [[ ("$VMWARE_DVS_USE_SS_SSL" = "true") || ("$VMWARE_DVS_USE_SS_SSL" = "True") ]]; then
	fl='/usr/local/lib/python2.7/dist-packages/oslo_vmware/service.py'
	sudo sed -i s/'self.verify = cacert if cacert else not insecure'/'self.verify = False'/ $fl
    fi
}


# Entry Points
# ------------

function configure_dvs_compute_driver {
    echo "Configuring Nova VCDriver for DVS"
    cp $NOVA_VIF $NOVA_VCDRIVER
    cp $NOVA_VM_UTIL $NOVA_VCDRIVER
}

function configure_vmware_dvs_config {
    echo "Networkin-vSphere: configure_vmware_dvs_config"
    iniset /$OVSVAPP_CONF_FILE DEFAULT host $VMWAREAPI_CLUSTER
    iniset /$OVSVAPP_CONF_FILE securitygroup enable_security_group $VMWARE_DVS_ENABLE_SG
    iniset /$OVSVAPP_CONF_FILE securitygroup firewall_driver $VMWARE_DVS_FW_DRIVER
    iniset /$OVSVAPP_CONF_FILE ml2_vmware vsphere_login $OVSVAPP_VCENTER_USERNAME
    iniset /$OVSVAPP_CONF_FILE ml2_vmware vsphere_hostname $OVSVAPP_VCENTER_IP
    iniset /$OVSVAPP_CONF_FILE ml2_vmware vsphere_password $OVSVAPP_VCENTER_PASSWORD
    iniset /$OVSVAPP_CONF_FILE ml2_vmware network_maps $OVSVAPP_CLUSTER_DVS_MAPPING
    iniset /$OVSVAPP_CONF_FILE ml2_vmware uplink_maps $VMWARE_DVS_UPLINK_MAPPING
    iniset /$NOVA_CONF DEFAULT host $VMWAREAPI_CLUSTER
}

function configure_ovsvapp_monitoring {
   echo "Configuring ml2_conf.ini for OVSvApp Monitoring"
   iniset /$Q_PLUGIN_CONF_FILE ovsvapp enable_ovsvapp_monitor $ENABLE_OVSVAPP_MONITOR
}

function configure_vmware_dvs_config {
    echo "Networkin-vSphere: configure_vmware_dvs_config"
    iniset /$VMWARE_DVS_CONF_FILE DEFAULT host $VMWAREAPI_CLUSTER
    iniset /$VMWARE_DVS_CONF_FILE securitygroup enable_security_group $VMWARE_DVS_ENABLE_SG
    iniset /$VMWARE_DVS_CONF_FILE securitygroup firewall_driver $VMWARE_DVS_FW_DRIVER
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware vsphere_login $VMWAREAPI_USER
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware vsphere_hostname $VMWAREAPI_IP
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware vsphere_password $VMWAREAPI_PASSWORD
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware network_maps $VMWARE_DVS_CLUSTER_DVS_MAPPING
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware uplink_maps $VMWARE_DVS_UPLINK_MAPPING
    iniset /$NOVA_CONF DEFAULT host $VMWAREAPI_CLUSTER
}

function start_ovsvapp_agent {
    echo "Starting OVSvApp Agent"
    run_process ovsvapp-agent "python $OVSVAPP_AGENT_BINARY --config-file $NEUTRON_CONF --config-file /$OVSVAPP_CONF_FILE"
}

function start_vmware_dvs_agent {
    echo "Networkin-vSphere: start_vmware_dvs_agent"
    VMWARE_DVS_AGENT_BINARY="$NEUTRON_BIN_DIR/neutron-dvs-agent"
    echo "Starting Vmware_Dvs Agent"
    run_process vmware_dvs-agent "python $VMWARE_DVS_AGENT_BINARY --config-file $NEUTRON_CONF --config-file /$VMWARE_DVS_CONF_FILE"
}

function setup_vmware_dvs_bridges {
    echo "Networkin-vSphere: setup_vmware_dvs_bridges"
    echo "Adding Bridges for Vmware_Dvs Agent"
    sudo ovs-vsctl --no-wait -- --may-exist add-br $INTEGRATION_BRIDGE
    sudo ovs-vsctl --no-wait -- --may-exist add-br $VMWARE_DVS_PHYSICAL_BRIDGE
    sudo ovs-vsctl --no-wait -- --may-exist add-port $VMWARE_DVS_PHYSICAL_BRIDGE $VMWARE_DVS_PHYSICAL_INTERFACE
}

function configure_ovsvapp_config {
    echo "Configuring ovsvapp_agent.ini for OVSvApp"
    iniset /$OVSVAPP_CONF_FILE vmware vcenter_ip $OVSVAPP_VCENTER_IP
    iniset /$OVSVAPP_CONF_FILE vmware vcenter_username $OVSVAPP_VCENTER_USERNAME
    iniset /$OVSVAPP_CONF_FILE vmware vcenter_password $OVSVAPP_VCENTER_PASSWORD
    iniset /$OVSVAPP_CONF_FILE vmware wsdl_location $OVSVAPP_WSDL_LOCATION
    iniset /$OVSVAPP_CONF_FILE vmware cluster_dvs_mapping $OVSVAPP_CLUSTER_DVS_MAPPING
    iniset /$OVSVAPP_CONF_FILE vmware esx_hostname $OVSVAPP_ESX_HOSTNAME
    if [ "$OVSVAPP_TENANT_NETWORK_TYPES" == "vxlan" ]; then
        iniset /$OVSVAPP_CONF_FILE ovsvapp tenant_network_types $OVSVAPP_TENANT_NETWORK_TYPES
        iniset /$OVSVAPP_CONF_FILE ovsvapp local_ip $OVSVAPP_LOCAL_IP
    else
        iniset /$OVSVAPP_CONF_FILE ovsvapp bridge_mappings $OVSVAPP_BRIDGE_MAPPINGS
    fi
    iniset /$OVSVAPP_CONF_FILE securitygroup security_bridge_mapping $OVSVAPP_SECURITY_BRIDGE_MAPPINGS
}

function add_ovsvapp_config {
    OVSVAPP_CONF_PATH=etc/neutron/plugins/ml2
    mkdir -p /$OVSVAPP_CONF_PATH
    OVSVAPP_CONF_FILE=$OVSVAPP_CONF_PATH/$OVSVAPP_CONF_FILENAME
    echo "Adding configuration file for OVSvApp Agent"
    cp $OVSVAPP_NETWORKING_DIR/$OVSVAPP_CONF_FILE /$OVSVAPP_CONF_FILE
}

function pre_configure_vmware_dvs {
    echo "Networkin-vSphere: pre_configure_vmware_dvs"
    echo "Configuring Neutron for Vmware_Dvs Agent"
    configure_neutron
    _configure_neutron_service
}

function install_vmware_dvs_dependency {
    echo "Networkin-vSphere: install_vmware_dvs_dependency"
    echo "Installing dependencies for VMware_DVS"
    install_nova
    install_neutron
    _neutron_ovs_base_install_agent_packages
    _when_vmware sudo pip install "git+git://github.com/yunesj/suds#egg=suds"
    _when_vmware _patch_oslo_vmware
}

function install_networking_vsphere {
    echo "Networkin-vSphere: install_networking_vsphere"
    echo "Installing the Networking-vSphere"
    setup_develop $VMWARE_DVS_NETWORKING_DIR
}

# main loop
if is_service_enabled vmware_dvs-server; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_vmware_dvs_dependency
        install_networking_vsphere

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # no-op
	:
    elif [[ "$1" == "stack" && "$2" == "post-extra" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "clean" ]]; then
        # no-op
        :
    fi
fi

if is_service_enabled vmware_dvs-agent; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_vmware_dvs_dependency
        install_networking_vsphere

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
	add_vmware_dvs_config
        configure_DVS_compute_driver
	configure_vmware_dvs_config
	setup_vmware_dvs_bridges
	start_vmware_dvs_agent
    elif [[ "$1" == "stack" && "$2" == "post-extra" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack" ]]; then
        cleanup_vmware_dvs_bridges
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_vmware_dvs_bridges
    fi
fi

if is_service_enabled vmware_dvs-server; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_ovsvapp_dependency
        install_networking_vsphere

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # no-op
	:
    elif [[ "$1" == "stack" && "$2" == "post-extra" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "clean" ]]; then
        # no-op
        :
    fi
fi

if is_service_enabled vmware_dvs-agent; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_ovsvapp_dependency
        install_networking_vsphere

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
	add_ovsvapp_config
        configure_dvs_compute_driver
	configure_vmware_dvs_config
	setup_ovsvapp_bridges
	start_ovsvapp_agent
    elif [[ "$1" == "stack" && "$2" == "post-extra" ]]; then
        # no-op
        :
    fi

    if [[ "$1" == "unstack" ]]; then
        cleanup_ovsvapp_bridges
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_ovsvapp_bridges
    fi
fi

# Restore xtrace
$XTRACE

# Tell emacs to use shell-script-mode
## Local variables:
## mode: shell-script
## End:
