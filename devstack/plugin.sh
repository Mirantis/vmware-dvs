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

# OVSvApp Networking-vSphere DIR.
VMWARE_DVS_NETWORKING_DIR=$DEST/networking-vsphere

# Entry Points
# ------------

function add_vmware_dvs_config {
    VMWARE_DVS_CONF_PATH=etc/neutron/plugins/ml2
    VMWARE_DVS_CONF_FILENAME=vmware_dvs_agent.ini
    mkdir -p /$VMWARE_DVS_CONF_PATH
    VMWARE_DVS_CONF_FILE=$VMWARE_DVS_CONF_PATH/$VMWARE_DVS_CONF_FILENAME
    echo "Adding configuration file for Vmware_Dvs Agent"
    cp $VMWARE_DVS_NETWORKING_DIR/$VMWARE_DVS_CONF_FILE /$VMWARE_DVS_CONF_FILE
}

function configure_vmware_dvs_config {
    echo "Configuring vmware_dvs_agent.ini for Vmware_Dvs"
    iniset /$VMWARE_DVS_CONF_FILE DEFAULT host $VMWAREAPI_CLUSTER
    iniset /$VMWARE_DVS_CONF_FILE securitygroup enable_security_group $VMWARE_DVS_ENABLE_SG
    iniset /$VMWARE_DVS_CONF_FILE securitygroup firewall_driver $VMWARE_DVS_FW_DRIVER
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware vsphere_login $VMWARE_IP
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware vsphere_hostname $VMWARE_USER
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware vsphere_password $VMWARE_PASSWORD
    iniset /$VMWARE_DVS_CONF_FILE ml2_vmware network_maps $VMWARE_DVS_CLUSTER_DVS_MAPPING
}

function start_vmware_dvs_agent {
    VMWARE_DVS_AGENT_BINARY="$NEUTRON_BIN_DIR/neutron-dvs-agent"
    echo "Starting Vmware_Dvs Agent"
    run_process vmware_dvs-agent "python $VMWARE_DVS_AGENT_BINARY --config-file $NEUTRON_CONF --config-file /$VMWARE_DVS_CONF_FILE"
}

function setup_vmware_dvs_bridges {
    echo "Adding Bridges for Vmware_Dvs Agent"
    sudo ovs-vsctl --no-wait -- --may-exist add-br $INTEGRATION_BRIDGE
    if [ "$VMWARE_DVS_TENANT_NETWORK_TYPE" == "vxlan" ]; then
        sudo ovs-vsctl --no-wait -- --may-exist add-br $TUNNEL_BRIDGE
    else
        sudo ovs-vsctl --no-wait -- --may-exist add-br $VMWARE_DVS_PHYSICAL_BRIDGE
        sudo ovs-vsctl --no-wait -- --may-exist add-port $VMWARE_DVS_PHYSICAL_BRIDGE $VMWARE_DVS_PHYSICAL_INTERFACE
    fi
    sudo ovs-vsctl --no-wait -- --may-exist add-br $SECURITY_BRIDGE
    sudo ovs-vsctl --no-wait -- --may-exist add-port $SECURITY_BRIDGE $VMWARE_DVS_TRUNK_INTERFACE
}

function cleanup_vmware_dvs_bridges {
    echo "Removing Bridges for Vmware_Dvs Agent"
    sudo ovs-vsctl del-br $INTEGRATION_BRIDGE
    sudo ovs-vsctl del-br $TUNNEL_BRIDGE
    sudo ovs-vsctl del-br $SECURITY_BRIDGE
    sudo ovs-vsctl del-br $VMWARE_DVS_PHYSICAL_BRIDGE
}

function pre_configure_vmware_dvs {
    echo "Configuring Neutron for Vmware_Dvs Agent"
    configure_neutron
    _configure_neutron_service
}

function install_vmware_dvs_dependency {
    echo "Installing dependencies for VMware_DVS"
    install_nova
    install_neutron
    _neutron_ovs_base_install_agent_packages
}

function install_networking_vsphere {
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
	pre_configure_vmware_dvs
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
	pre_configure_vmware_dvs
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
	add_vmware_dvs_config
	configure_vmware_dvs_config
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

# Restore xtrace
$XTRACE

# Tell emacs to use shell-script-mode
## Local variables:
## mode: shell-script
## End:
