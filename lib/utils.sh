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
    printf "%$(($SYSINFO_TITLE_WIDTH+1))s" " "
}

# Print state with coloured OK/FAIL prefix
function state() {
    local msg=$1
    local flag=$2
    if [ $flag -eq 0 ]; then
        echo -e "\e[92m PASS \033[0m $msg"
    elif [ $flag -eq 2 ]; then
        echo -e "\e[93m WARN \033[0m $msg"
    else
        echo -e "\e[91m FAIL \033[0m $msg"
    fi
}

function service_cmd() {
    if is_centos_rhel_7; then
        echo "systemctl status $service"
    else
        echo "service $service status"
    fi
}

function _validate_service_state() {
    local prefix=$1
    local service=$2
    sudo `service_cmd` &>/dev/null
    echo $?
}

function _check_service_is_running() {
    local prefix=$1
    local service=$2
    local msgflag=${3:-1}
    if is_centos_rhel_7; then
        # Check the running status of the service (RHEL/CentOS7)
        local sub_state=`systemctl show $service --type=service --property=SubState | sed -e 's/^.*=//'`
        if [[ $sub_state = 'running' ]]; then
            state "$prefix: $service is running" 0
            SERVICE_STATUS['running']=true
        else
            state "$prefix: $service is not running" $msgflag
            SERVICE_STATUS['running']=false
        fi
        # Check the load state of the service (RHEL/CentOS7)
        local load_state=`systemctl show $service --type=service --property=LoadState | sed -e 's/^.*=//'`
        case $load_state in
            'loaded')
                systemctl is-enabled $service --type=service --quiet
                if [[ $? -eq 0 ]]; then
                    state "$prefix: $service auto-starts on boot" 0
                    SERVICE_STATUS['auto-start']=true
                else
                    state "$prefix: $service does not auto-start on boot" $msgflag
                    SERVICE_STATUS['auto-start']=false
                fi
                SERVICE_STATUS['installed']=true
                ;;
            'not-found')
                state "$prefix: $service is not loaded, so won't auto-start on boot" $msgflag
                SERVICE_STATUS['auto-start']=false
                SERVICE_STATUS['installed']=false
                ;;
            *)
                echo "Error: Uknown LoadState=$load_state for ${service}.service"
                SERVICE_STATUS['auto-start']=false
                SERVICE_STATUS['installed']=false
                ;;
        esac
    else
        # Check the running status of the service (RHEL/CentOS6)
        sudo `service_cmd` &>/dev/null
        case $? in
            0)
                state "$prefix: $service is running" 0
                SERVICE_STATUS['running']=true
                SERVICE_STATUS['installed']=true
                ;;
            3)
                state "$prefix: $service is not running" $msgflag
                SERVICE_STATUS['running']=false
                SERVICE_STATUS['installed']=true
                ;;
            *)
                state "$prefix: $service is not installed" $msgflag
                SERVICE_STATUS['running']=false
                SERVICE_STATUS['installed']=false
                ;;
        esac
        # Check the runlevel information of the service (RHEL/CentOS6)
        local chkconfig=`chkconfig 2>/dev/null | awk "/^$service / {print \\$5}"`
        [ "$chkconfig" ] || chkconfig=""
        if [ "$chkconfig" = "3:on" ]; then
            state "$prefix: $service auto-starts on boot" 0
            SERVICE_STATUS['auto-start']=true
        else
            state "$prefix: $service does not auto-start on boot" $msgflag
            SERVICE_STATUS['auto-start']=false
        fi
    fi
}

function _check_service_is_not_running() {
    local prefix=$1
    local service=$2
    if is_centos_rhel_7; then
        # Check the running status of the service (RHEL/CentOS7)
        local sub_state=`systemctl show $service --type=service --property=SubState | sed -e 's/^.*=//'`
        if [[ $sub_state = 'running' ]]; then
            state "$prefix: $service should not running" 1
        else
            state "$prefix: $service is not running" 0
        fi
        # Check the load state of the service (RHEL/CentOS7)
        local load_state=`systemctl show $service --type=service --property=LoadState | sed -e 's/^.*=//'`
        case $load_state in
            'loaded')
                systemctl is-enabled $service --type=service --quiet
                if [[ $? -eq 0 ]]; then
                    state "$prefix: $service should not auto-start on boot" 1
                else
                    state "$prefix: $service does not auto-start on boot" 0
                fi
                ;;
            'not-found')
                state "$prefix: $service is not loaded, so won't auto-start on boot" 0
                ;;
            *)
                echo "Error: Unknown LoadState=$load_state for ${service}.service"
                ;;
        esac
    else
        # Check the running status of the service (RHEL/CentOS6)
        sudo `service_cmd` &>/dev/null
        case $? in
            0) state "$prefix: $service should not running" 1
                if [ "$service" = "iptables" ]; then
                    echo "       iptable routes:"
                    sudo iptables -L | sed "s/^/         /"
                fi;;
            3) state "$prefix: $service is not running"   0;;
            *) state "$prefix: $service is not installed" 1;;
        esac
        # Check the runlevel information of the service (RHEL/CentOS6)
        local chkconfig=`chkconfig 2>/dev/null | awk "/^$service / {print \\$5}"`
        [ "$chkconfig" ] || chkconfig=""
        if [ "$chkconfig" = "3:on" ]; then
            if [ "$service" = "sssd" ]; then
                state "$prefix: $service should not auto-start on boot" 2
            else
                state "$prefix: $service should not auto-start on boot" 1
            fi
        else
            state "$prefix: $service does not auto-start on boot" 0
        fi
    fi
}

function is_centos_rhel_7() {
    if [ -f /etc/redhat-release ] && grep -q " 7." /etc/redhat-release; then
        return 0;
    else
        return 1;
    fi
}
