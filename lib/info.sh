#!/usr/bin/env bash

function print_time() {
    local timezone
    timezone=$(date | awk '{print $(NF-1)}')
    timezone=${timezone:-UTC}
    print_label "Timezone" "$timezone"
    print_label "DateTime" "$(date)"
}

function print_fqdn() {
    print_label "FQDN" "$(hostname -f)"
}

function print_os() {
    local distro="Unknown"
    if [ -f /etc/redhat-release ]; then
        distro=$( sed -e 's/ release / /' \
            -e 's/ ([[:alnum:]]*)//' \
            -e 's/CentOS Linux \([0-9]\).\([0-9]\).*/CentOS \1.\2/' \
            /etc/redhat-release )
    fi
    print_label "Distro" "$distro"
    print_label "Kernel" "$(uname -r)"
}

function print_cpu_and_ram() {
    local cpu
    cpu=$(grep -m1 "^model name" /proc/cpuinfo | cut -d' ' -f3- | sed -e 's/(R)//' -e 's/Core(TM) //' -e 's/CPU //')
    print_label "CPUs" "$(nproc)x $cpu"
    # Total installed memory (MemTotal and SwapTotal in /proc/meminfo)
    print_label "RAM" "$(awk '/^MemTotal:/ { printf "%.2f", $2/1024/1024 ; exit}' /proc/meminfo)G"
}

function print_swap() {
   local swap
   swap=$(free -h | awk '/^Swap:/{print $2}')
   if [ -z "$swap" ]
   then
      swap="(None)"
   fi
   print_label "Swap" "$swap"
}

function print_disks() (
    function data_mounts() {
        while read -r source target fstype options; do
            local NOATIME=false
            for option in $(echo "$options" | tr ',' ' '); do
                if [[ $option = 'noatime' ]]; then
                    NOATIME=true
                fi
            done
            echo -n "$source $target "
            case $fstype in
                'xfs')
                    local resblks
                    resblks=$(xfs_io -xc resblks "$target" | awk '/^reserved blocks =/ { print $4 }')
                    echo -en "\e[92m$fstype\033[0m, "
                    if [[ $resblks -eq 0 ]]; then
                        echo -en "\e[92mNo\033[0m reserved blocks, "
                    else
                        echo -en "\e[93m$resblks\033[0m blocks reserved, "
                    fi
                    if ${NOATIME}; then
                        echo -e "\e[92mnoatime\033[0m option specified|"
                    else
                        echo -e "without \e[93mnoatime\033[0m option|"
                    fi
                    ;;
                'ext3'|'ext4')
                    local resblks
                    resblks=$(tune2fs -l "$source" | awk '/^Reserved block count:/ { print $4 }')
                    echo -en "\e[92m$fstype\033[0m, "
                    if [[ $resblks -eq 0 ]]; then
                        echo -en "\e[92mNo\033[0m reserved blocks, "
                    else
                        echo -en "\e[93m$resblks\033[0m blocks reserved, "
                    fi
                    if ${NOATIME}; then
                        echo -e "\e[92mnoatime\033[0m option specified|"
                    else
                        echo -e "without \e[93mnoatime\033[0m option|"
                    fi
                    ;;
                *)
                    echo -e "\e[91m$fstype\033[0m is not recommended for a data mount|"
                    ;;
            esac
        done
    }
    echo "Disks:"
    # shellcheck disable=SC2045
    for d in $(find /dev/{sd?,xvd?} -type b 2>/dev/null | sort); do
        pad; echo -n "$d  "
        sudo fdisk -l "$d" 2>/dev/null | grep "^Disk /dev/" | cut -d' ' -f3-4 | cut -d',' -f1
    done
    echo "Mount:"
    findmnt -lo source,target,fstype,options | sort | grep '^/dev' | \
        while read -r line; do
            pad; echo "$line"
        done
    echo "Data mounts:"
    local DATA_MOUNTS
    DATA_MOUNTS=$( findmnt -lno source,target,fstype,options | sort | \
        grep -E '[[:space:]]/data' | data_mounts )
    if [[ -z ${DATA_MOUNTS} ]]; then
        pad; echo "None found"
    else
        local IFS='|'
        echo "$DATA_MOUNTS" | while read -r line; do
            pad; echo "$line"
        done
    fi
)

function print_free_space() (
    function free_space() {
        # Pick "Avail" column as "Free space:"
        # $ df -Ph /opt
        # Filesystem      Size  Used Avail Use% Mounted on
        # /dev/sda1        99G  1.8G   92G   2% /
        test -d "$1" || return 0
        local path="$1"
        local data
        local free
        local total
        data=$(df -Ph "$path" | tail -1)
        free=$(echo "$data" | awk '{print $4}')
        total=$(echo "$data" | awk '{print $2}')
        pad
        printf "%-9s %s\n" "$path" "$free of $total"
    }
    echo "Free space:"
    free_space /
    free_space /home
    free_space /opt
    free_space /opt/cloudera
    free_space /tmp
    free_space /usr
    free_space /usr/hdp
    free_space /var
    free_space /var/lib
    free_space /var/log
)

function print_cloudera_rpms() {
    local rpms
    rpms=$(echo -e "$RPM_QA" | grep "^cloudera-")
    if [ "$rpms" ]; then
        echo "Cloudera RPMs:"
        local pkg
        local ver
        for line in $rpms; do
            pkg=$(echo "$line" | cut -d'-' -f1-3)
            ver=$(echo "$line" | cut -d'-' -f4-)
            pad
            printf "%-24s  %s\n" "$pkg" "$ver"
        done
    else
        echo "Cloudera RPMs: None installed"
    fi
}

function print_network() {
    echo "Networks Cards:"
    local iface
    local iface_name
    local iface_status
    local iface_speed
    local iface_duplex
    local iface_path="/sys/class/net"
    for iface in $iface_path/*
    do
        if [ -d $iface ]
        then
            if cat "$iface/speed" >/dev/null 2>&1
            then
                iface_name=$(echo "$iface" | sed 's/^.*\/\(.*\)$/\1/')
                iface_status=$(cat $iface/operstate)
                iface_speed=$(cat $iface/speed)
                iface_duplex=$(cat $iface/duplex)
                pad; echo "$iface_name ($iface_status $iface_speed $iface_duplex)"
            fi
        fi
    done
    print_label "nsswitch" "$(grep "^hosts:" /etc/nsswitch.conf | sed 's/^hosts: *//')"
    print_label "DNS server" "$(awk '/^nameserver/{printf $2 " "}' /etc/resolv.conf)"
}

function print_internet() {
  if [ "$(ping -W1 -c1 8.8.8.8 &>/dev/null; echo $?)" -eq 0 ]; then
    print_label "Internet" "Yes"
  else
    print_label "Internet" "No"
  fi
}

function system_info() {
    print_header "System information"
    print_fqdn
    print_os
    print_cpu_and_ram
    print_swap
    print_disks
    print_free_space
    print_cloudera_rpms
    print_time
    print_network
    print_internet
}
