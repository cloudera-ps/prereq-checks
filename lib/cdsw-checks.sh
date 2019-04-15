#!/usr/bin/env bash

function check_localhost() {
    which dig 2&>/dev/null
    if [ $? -eq 2 ]; then
        state "Network: 'dig' not found, skipping localhost check. Run 'sudo yum install bind-utils' to fix." 2
        return
    fi

    ip=$(dig +short localhost)
    if [[ $ip = '127.0.0.1' ]]; then
        state "Network: localhost correctly resolves to 127.0.0.1" 0
    else
        state "Network: localhost does not resolve to 127.0.0.1" 1
    fi
    return 
}

function check_iptable() {
    NUM_RULES=$(iptables -n -L -v --line-numbers | egrep "^[0-9]" | wc -l)
    state "System: iptables should not have any pre-existing rules" $([ "$NUM_RULES" == 0 ] && echo "0" || echo "1")
    return
}

function check_wildcard_dns() {

    which dig 2&>/dev/null
    if [ $? -eq 2 ]; then
        state "Network: 'dig' not found, skipping wildcard DNS checks. Run 'sudo yum install bind-utils' to fix." 2
        return
    fi

    rand=$(openssl rand -hex 3)
    ip=$(dig +short $rand.$ARG_CDSW_FQDN)

    if [[ "$ip" == "$ARG_CDSW_MASTER_IP" ]]; then
        state "Network: wildcard DNS correctly resolves to CDSW Master IP $ARG_CDSW_MASTER_IP" 0
    else
        state "Network: wildcard DNS does not resolve to the CDSW Master IP" 1
    fi
    return
}

function check_local_dns_port53() {
    # Check if port 53 is in used by other service
    if [[ -z "$(netstat -na | grep ":53 " | awk '{print $4}' | grep -E '^(0.0.0.0|127.0.0.1)')" ]]; then
        state "Network: port 53 should not be used by other service on CDSW master" 0
    else
        state "Network: port 53 should not be used by other service on CDSW master" 1
    fi
}

function check_uid_8536() {
    user=$(id -un 8536 2> /dev/null)
    if [[ $? -eq 1 ]]; then
        state "System: user id 8536 is not in use" 0
    else
        state "System: user id 8536 is used ($user)" 1
    fi
    return
}

function check_app_blk_dev() {
    df=$(df |grep /var/lib/cdsw)

    if [[ -z "$df" ]]; then
        state "System: application block device for /var/lib/cdsw not found" 1
        return
    fi

    appdev=$(echo $df | awk '{print $1}')
    size=$(echo $df | awk '{print $2}')
    
    if [[ $size -gt 1099511627776 ]]; then
        state "System: found application block device $appdev with at least 1TB size mounted to /var/lib/cdsw" 0
    else
        state "System: found application block device $appdev but size is less than 1TB" 2
    fi

    return
}

function print_raw_blk_dev() {
    echo "Block Devices:"

    blkdev=$(lsblk -ndlp -o name,type | grep disk| awk '{print $1}')

    for dev in $blkdev; do
        if [[ $(lsblk -nlp $dev | wc -l) -gt 1 ]]; then
            continue
        else
            # get size of device
            size=$(lsblk -n -o size $dev)

            pad
            # check if device has a GPT partition or MBR
            output=$(blkid -o value $dev)
            if [[ $output == "dos" ]]; then
               printf "%s\t%s\t%s\n" "$dev" "$size" "MBR" 
            elif [[ $output == "gpt" ]]; then
               printf "%s\t%s\t%s\n" "$dev" "$size" "GPT"
            else
               printf "%s\t%s\t%s\n" "$dev" "$size" "None"
            fi
        fi
    done
}

function check_root_vol() {
    return
}

function check_cdsw() {
    echo ""
    echo "System information"
    echo "------------------"
    print_fqdn
    print_os
    print_cpu_and_ram
    print_time
    print_network
    print_raw_blk_dev

    echo ""
    echo "CDSW prerequisite checks"
    echo "------------------------"

    check_uid_8536
    check_app_blk_dev
    check_iptable
    check_localhost
    check_wildcard_dns
    check_local_dns_port53
    return
}
