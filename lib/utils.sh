#!/usr/bin/env bash

# Global array variable for passing service state. Set by get_service_state().
declare -A SERVICE_STATE

SYSINFO_TITLE_WIDTH=14

function print_label() {
    printf "%-${SYSINFO_TITLE_WIDTH}s %s\n" "$1:" "$2"
}

function print_header() {
    echo
    echo "$*"
    echo "-------------------"
}

function pad() {
    printf "%$((SYSINFO_TITLE_WIDTH+1))s" " "
}

# Print state with coloured OK/FAIL prefix
function state() {
    local msg=$1
    local flag=$2
    if [ "$flag" -eq 0 ]; then
        echo -e "\e[92m PASS \033[0m $msg"
    elif [ "$flag" -eq 2 ]; then
        echo -e "\e[93m WARN \033[0m $msg"
    else
        echo -e "\e[91m FAIL \033[0m $msg"
    fi
}

# Checks that the specified service is installed, running, and auto-started on boot.
function _check_service_is_running() {
    local prefix="$1"
    local service_name="$2"
    local msgflag="${3:-1}"

    [ -z "$prefix" ]       && die "Prefix not specified"
    [ -z "$service_name" ] && die "Service name not specified"

    get_service_state "$service_name"

    if [ "${SERVICE_STATE['installed']}" = true ]; then
        if [ "${SERVICE_STATE['running']}" = true ]; then
            state "$prefix: $service_name is running" 0
        else
            state "$prefix: $service_name is not running" "$msgflag"
        fi

        if [ "${SERVICE_STATE['autostart']}" = true ]; then
            state "$prefix: $service_name auto-starts on boot" 0
        else
            state "$prefix: $service_name does not auto-start on boot" "$msgflag"
        fi
    else
        state "$prefix: $service_name is not installed" "$msgflag"
    fi
}

# Checks that the specified service is NOT installed, running, or auto-started on boot.
function _check_service_is_not_running() {
    local prefix="$1"
    local service_name="$2"
    local msgflag="${3:-1}"

    [ -z "$prefix" ]       && die "Prefix not specified"
    [ -z "$service_name" ] && die "Service name not specified"

    get_service_state "$service_name"

    if [ "${SERVICE_STATE['installed']}" = true ]; then
        if [ "${SERVICE_STATE['running']}" = true ]; then
            state "$prefix: $service_name should not be running" "$msgflag"
        else
            state "$prefix: $service_name is not running" 0
        fi

        if [ "${SERVICE_STATE['autostart']}" = true ]; then
            state "$prefix: $service_name should not auto-start on boot" "$msgflag"
        else
            state "$prefix: $service_name does not auto-start on boot" 0
        fi
    else
        state "$prefix: $service_name is not installed" 0
    fi
}

function is_centos_rhel_7() {
    if [ -f /etc/redhat-release ] && grep -q " 7." /etc/redhat-release; then
        return 0;
    else
        return 1;
    fi
}

function reset_service_state() {
    SERVICE_STATE['installed']=false
    SERVICE_STATE['running']=false
    SERVICE_STATE['autostart']=false
}

function die() {
    echo "ERROR: $*. Aborting!"
    exit 2
}

function get_service_state() {
    local service_name="$1"

    [ -z "$service_name" ] && die "Service name not specified"

    reset_service_state

    if is_centos_rhel_7; then
        local sub_state
        sub_state=$(systemctl show "$service_name" --type=service --property=SubState 2</dev/null | sed -e 's/^.*=//')
        case $sub_state in
            'running')  SERVICE_STATE['installed']=true
                        SERVICE_STATE['running']=true
                        ;;
            'dead')     SERVICE_STATE['installed']=true
                        ;;
        esac

        systemctl is-enabled "$service_name" --type=service --quiet 2</dev/null
        case $? in
            0)  SERVICE_STATE['autostart']=true
                ;;
        esac
    else
        # Most services don't need sudo, but some like iptables do even for status.
        sudo service "$service_name" status 2&>/dev/null
        case $? in
            0)  SERVICE_STATE['installed']=true
                SERVICE_STATE['running']=true
                ;;
            3)  SERVICE_STATE['installed']=true
                ;;
        esac

        local autostart
        autostart=$(chkconfig 2>/dev/null | awk "/^$service_name / {print \$5}")
        if [ "$autostart" = "3:on" ]; then
            SERVICE_STATE['autostart']=true
        fi
    fi

    if [ "$DEBUG" = true ]; then
        echo "$service_name installed: ${SERVICE_STATE['installed']}"
        echo "$service_name running:   ${SERVICE_STATE['running']}"
        echo "$service_name autostart: ${SERVICE_STATE['autostart']}"
    fi
}
