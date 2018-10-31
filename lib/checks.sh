#!/usr/bin/env bash

function check_java() {
    # The following candidate list is from CM agent:
    # Starship/cmf/agents/cmf/service/common/cloudera-config.sh
    local JAVA6_HOME_CANDIDATES=(
        '/usr/lib/j2sdk1.6-sun'
        '/usr/lib/jvm/java-6-sun'
        '/usr/lib/jvm/java-1.6.0-sun-1.6.0'
        '/usr/lib/jvm/j2sdk1.6-oracle'
        '/usr/lib/jvm/j2sdk1.6-oracle/jre'
        '/usr/java/jdk1.6'
        '/usr/java/jre1.6'
    )
    local OPENJAVA6_HOME_CANDIDATES=(
        '/usr/lib/jvm/java-1.6.0-openjdk'
        '/usr/lib/jvm/jre-1.6.0-openjdk'
    )
    local JAVA7_HOME_CANDIDATES=(
        '/usr/java/jdk1.7'
        '/usr/java/jre1.7'
        '/usr/lib/jvm/j2sdk1.7-oracle'
        '/usr/lib/jvm/j2sdk1.7-oracle/jre'
        '/usr/lib/jvm/java-7-oracle'
    )
    local OPENJAVA7_HOME_CANDIDATES=(
        '/usr/lib/jvm/java-1.7.0-openjdk'
        '/usr/lib/jvm/java-7-openjdk'
    )
    local JAVA8_HOME_CANDIDATES=(
        '/usr/java/jdk1.8'
        '/usr/java/jre1.8'
        '/usr/lib/jvm/j2sdk1.8-oracle'
        '/usr/lib/jvm/j2sdk1.8-oracle/jre'
        '/usr/lib/jvm/java-8-oracle'
    )
    local OPENJAVA8_HOME_CANDIDATES=(
        '/usr/lib/jvm/java-1.8.0-openjdk'
        '/usr/lib/jvm/java-8-openjdk'
    )
    local MISCJAVA_HOME_CANDIDATES=(
        '/Library/Java/Home'
        '/usr/java/default'
        '/usr/lib/jvm/default-java'
        '/usr/lib/jvm/java-openjdk'
        '/usr/lib/jvm/jre-openjdk'
    )
    local JAVA_HOME_CANDIDATES=(
        ${JAVA7_HOME_CANDIDATES[@]}
        ${JAVA8_HOME_CANDIDATES[@]}
        ${JAVA6_HOME_CANDIDATES[@]}
        ${MISCJAVA_HOME_CANDIDATES[@]}
        ${OPENJAVA7_HOME_CANDIDATES[@]}
        ${OPENJAVA8_HOME_CANDIDATES[@]}
        ${OPENJAVA6_HOME_CANDIDATES[@]}
    )

    # Find and verify Java
    # https://www.cloudera.com/documentation/enterprise/release-notes/topics/rn_consolidated_pcm.html#pcm_jdk
    # JDK 7 minimum required version is JDK 1.7u55
    # JDK 8 minimum required version is JDK 1.8u31
    #   excluldes JDK 1.8u40, JDK 1.8u45, and JDK 1.8u60
    for candidate_regex in "${JAVA_HOME_CANDIDATES[@]}"; do
        # shellcheck disable=SC2045,SC2086
        for candidate in $(ls -rvd ${candidate_regex}* 2>/dev/null); do
            if [ -x "$candidate/bin/java" ]; then
                JDK_VERSION=$($candidate/bin/java -version 2>&1 | head -1 | awk '{print $NF}' | tr -d '"')
                JDK_VERSION_REGEX='1\.([0-9])\.0_([0-9][0-9]*)'
                JDK_TYPE=$($candidate/bin/java -version 2>&1 | head -2 | tail -1 | awk '{print $1}')
                if [[ $JDK_TYPE = "Java(TM)" ]]; then
                    if [[ $JDK_VERSION =~ $JDK_VERSION_REGEX ]]; then
                        if [[ ${BASH_REMATCH[1]} -eq 7 ]]; then
                            if [[ ${BASH_REMATCH[2]} -lt 55 ]]; then
                                state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                            else
                                state "Java: Supported Oracle Java: ${candidate}/bin/java" 0
                            fi
                        elif [[ ${BASH_REMATCH[1]} -eq 8 ]]; then
                            if [[ ${BASH_REMATCH[2]} -lt 31 ]]; then
                                state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                            elif [[ ${BASH_REMATCH[2]} -eq 40 ]]; then
                                state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                            elif [[ ${BASH_REMATCH[2]} -eq 45 ]]; then
                                state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                            elif [[ ${BASH_REMATCH[2]} -eq 60 ]]; then
                                state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                            elif [[ ${BASH_REMATCH[2]} -eq 75 ]]; then
                                state "Java: Oozie will not work on this Java (OOZIE-2533): ${candidate}/bin/java" 2
                            else
                                state "Java: Supported Oracle Java: ${candidate}/bin/java" 0
                            fi
                        else
                            state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                        fi
                    else
                        state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                    fi
                elif [[ $JDK_TYPE = "OpenJDK" ]]; then
                    state "Java: Unsupported OpenJDK: ${candidate}/bin/java" 1
                else
                    state "Java: Unsupported Unknown: ${candidate}/bin/java" 1
                fi
            fi
        done
    done
}

function check_os() (
    function check_swappiness() {
        # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__section_xpq_sdf_jq
        local swappiness
        local msg="System: /proc/sys/vm/swappiness should be 1"
        swappiness=$(cat /proc/sys/vm/swappiness)
        if [ "$swappiness" -eq 1 ]; then
            state "$msg" 0
        else
            state "$msg. Actual: $swappiness" 1
        fi
    }

    function check_overcommit_memory() {
        # https://www.cloudera.com/documentation/enterprise/5-15-x/topics/impala_scalability.html#kerberos_overhead_memory_usage
        local overcommit_memory
        local msg="System: /proc/sys/vm/overcommit_memory should be 1"
        overcommit_memory=$(cat /proc/sys/vm/overcommit_memory)
        if [ "$overcommit_memory" -eq 1 ]; then
            state "$msg" 0
        else
            state "$msg. Actual: $overcommit_memory" 1
        fi
    }

    function check_tuned() {
        # "tuned" service should be disabled on RHEL/CentOS 7.x
        # https://www.cloudera.com/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__disable-tuned
        if is_centos_rhel_7; then
            systemctl status tuned &>/dev/null
            case $? in
                0) state "System: tuned is running" 1;;
                3) state "System: tuned is not running" 0;;
                *) state "System: tuned is not installed" 0;;
            esac
            if [ "$(systemctl is-enabled tuned 2>/dev/null)" == "enabled" ]; then
                state "System: tuned auto-starts on boot" 1
            else
                state "System: tuned does not auto-start on boot" 0
            fi
        fi
    }

    function check_thp() {
        # Older RHEL/CentOS versions use [1], while newer versions (e.g. 7.1) and
        # Ubuntu/Debian use [2]:
        #   1: /sys/kernel/mm/redhat_transparent_hugepage/defrag
        #   2: /sys/kernel/mm/transparent_hugepage/defrag.
        # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__section_hw3_sdf_jq
        local file
        file=$(find /sys/kernel/mm/ -type d -name '*transparent_hugepage')/defrag
        if [ -f "$file" ]; then
            local msg="System: $file should be disabled"
            if grep -F -q "[never]" "$file"; then
                state "$msg" 0
            else
                state "$msg. Actual: $(awk '{print $1}' "$file" | sed -e 's/\[//' -e 's/\]//')" 1
            fi
        else
            state "System: /sys/kernel/mm/*transparent_hugepage not found. Check skipped" 2
        fi
    }

    function check_selinux() {
        # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/install_cdh_disable_selinux.html
        local msg="System: SELinux should be disabled"
        case $(getenforce) in
            Disabled|Permissive) state "$msg" 0;;
            *)                   state "$msg. Actual: $(getenforce)" 1;;
        esac
    }

    # Check that the system clock is synced by either ntpd or chronyd. Chronyd
    # is on CentOS/RHEL 7 and above only.
    # https://community.cloudera.com/t5/Cloudera-Manager-Installation/Should-Cloudera-NTP-use-Chrony-or-NTPD/td-p/55986
    function check_time_sync() (
        function is_ntp_in_sync() {
            if [ "$(ntpstat | grep -c "synchronised to NTP server")" -eq 1 ]; then
                state "System: ntpd clock synced" 0
            else
                state "System: ntpd clock NOT synced. Check 'ntpstat'" 1
            fi
        }

        if is_centos_rhel_7; then
            get_service_state 'ntpd'
            if [ "${SERVICE_STATE['running']}" = true ]; then
                # If ntpd is running, then chrony shouldn't be
                _check_service_is_running 'System' 'ntpd'
                is_ntp_in_sync
                _check_service_is_not_running 'System' 'chronyd'
            else
                _check_service_is_running 'System' 'chronyd'
            fi
        else
            _check_service_is_running 'System' 'ntpd'
        fi
    )

    function check_32bit_packages() {
        local packages_32bit
        packages_32bit=$(rpm -qa --queryformat '\t%{NAME} %{ARCH}\n' | grep 'i[6543]86' | cut -d' ' -f1)
        if [ "$packages_32bit" ]; then
            state "System: Found the following 32bit packages installed:\n$packages_32bit" 1
        else
            state "System: Only 64bit packages should be installed" 0
        fi
    }

    function check_unneeded_services() {
        local UNNECESSARY_SERVICES=(
            'bluetooth'
            'cups'
            'ip6tables'
            'postfix'
        )
        for service_name in "${UNNECESSARY_SERVICES[@]}"; do
            _check_service_is_not_running 'System' "$service_name" 2
        done
    }

    function check_tmp_noexec() {
        local noexec=false
        for option in $(findmnt -lno options --target /tmp | tr ',' ' '); do
            if [[ "$option" = 'noexec' ]]; then
                noexec=true
            fi
        done
        if $noexec; then
            state "System: /tmp mounted with noexec fails for CM versions older than 5.8.4, 5.9.2, and 5.10.0" 2
        else
            state "System: /tmp mounted with noexec fails for CM versions older than 5.8.4, 5.9.2, and 5.10.0" 0
        fi
    }
    function check_entropy() {
        local entropy
        entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        if [ "$entropy" -gt 500 ]; then
            state "System: Entropy is $entropy" 0
        else
            state "System: Entropy should be more than 500, Actual: $entropy -- Please see https://bit.ly/2IoOj0K" 2
        fi
    }
    check_swappiness
    check_overcommit_memory
    check_tuned
    check_thp
    check_selinux
    check_time_sync
    check_32bit_packages
    check_unneeded_services
    check_tmp_noexec
    check_entropy
)

function check_database() {
    local VERSION_PATTERN='([0-9][0-9]*\.[0-9][0-9]*)\.[0-9][0-9]*'
    local mysql_ver=''
    local mysql_rpm=''
    local mysql_ent
    local mysql_com

    mysql_ent=$(rpm -q --queryformat='%{VERSION}' mysql-commercial-server)
    # shellcheck disable=SC2181
    if [[ $? -eq 0 ]]; then
        mysql_rpm=$(rpm -q mysql-commercial-server)
        [[ $mysql_ent =~ $VERSION_PATTERN ]]
        mysql_ver=${BASH_REMATCH[1]}
    fi

    mysql_com=$(rpm -q --queryformat='%{VERSION}' mysql-community-server)
    # shellcheck disable=SC2181
    if [[ $? -eq 0 ]]; then
        mysql_rpm=$(rpm -q mysql-community-server)
        [[ $mysql_com =~ $VERSION_PATTERN ]]
        mysql_ver=${BASH_REMATCH[1]}
    fi
    if [[ -z "$mysql_ver" ]]; then
        state "Database: MySQL server not installed, skipping version check" 2
        return
    fi

    case "$mysql_ver" in
        '5.1'|'5.5'|'5.6'|'5.7')
            state "Database: Supported MySQL server installed. $mysql_rpm" 0
            ;;
        *)
            state "Database: Unsupported MySQL server installed. $mysql_rpm" 1
            ;;
    esac
}

function check_jdbc_connector() {
    # See Installing the MySQL JDBC Driver
    # https://www.cloudera.com/documentation/enterprise/latest/topics/cm_ig_mysql.html#cmig_topic_5_5_3
    local connector=/usr/share/java/mysql-connector-java.jar
    if [ -f $connector ]; then
        state "Database: MySQL JDBC Driver is installed" 0
    else
        state "Database: MySQL JDBC Driver is not installed" 2
    fi
}

function check_network() (

    function check_hostname() {
        local fqdn
        local short
        fqdn=$(hostname -f)
        short=$(hostname -s)

        # https://en.wikipedia.org/wiki/Hostname
        # Hostnames are composed of series of labels concatenated with dots, as are
        # all domain names. Each label must be from 1 to 63 characters long, and the
        # entire hostname (including delimiting dots but not a trailing dot) has a
        # maximum of 253 ASCII characters.
        local VALID_FQDN='^([a-z]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9\-]{0,61}[a-z0-9])?$'
        echo "$fqdn" | grep -Eiq "$VALID_FQDN"
        local valid_format=$?
        if [[ $valid_format -eq 0 && ${#fqdn} -le 253 ]]; then
            if [[ ${#short} -gt 15 ]]; then
                # Microsoft still recommends computer names less than or equal to 15 characters.
                # https://serverfault.com/questions/123343/is-the-netbios-limt-of-15-charactors-still-a-factor-when-naming-computers
                # https://technet.microsoft.com/en-us/library/cc731383.aspx
                # If hostname is longer than that, we cannot do SSSD or Centrify etc to
                # add the node to domain. Won't work well with Kerberos/AD.
                state "Network: Computer name should be <= 15 characters (NetBIOS restriction)" 1
            else
                if [[ "${fqdn//\.*/}" = "$short" ]]; then
                    if [[ $(echo "$fqdn" | grep '[A-Z]') = "" ]]; then
                        state "Network: Hostname looks good (FQDN, no uppercase letters)" 0
                    else
                        # Cluster hosts must have a working network name resolution system and
                        # correctly formatted /etc/hosts file. All cluster hosts must have properly
                        # configured forward and reverse host resolution through DNS.
                        # The /etc/hosts files must:
                        # - Not contain uppercase hostnames
                        # https://www.cloudera.com/documentation/enterprise/release-notes/topics/rn_consolidated_pcm.html#cm_cdh_compatibility
                        state "Network: Hostname should not contain uppercase letters" 1
                    fi
                else
                    state "Network: Hostname misconfiguration (shortname and host label of FQDN don't match)" 2
                fi
            fi
        else
            # Important
            # - The canonical name of each host in /etc/hosts `must' be the FQDN
            # - Do not use aliases, either in /etc/hosts or in configuring DNS
            # https://www.cloudera.com/documentation/enterprise/latest/topics/cdh_ig_networknames_configure.html
            state "Network: Malformed hostname is configured (consult RFC)" 1
        fi
    }

    # Networking Protocols Support
    # CDH requires IPv4. IPv6 is not supported and must be disabled.
    # https://www.cloudera.com/documentation/enterprise/release-notes/topics/rn_consolidated_pcm.html
    function check_ipv6() {
        local msg="Network: IPv6 is not supported and must be disabled"
        if ip addr show | grep -q inet6; then
            state "${msg}" 1
        else
            state "${msg}" 0
        fi
    }

    function check_etc_hosts() {
        local entries
        entries=$(grep -cEv "^#|^ *$" /etc/hosts)
        local msg="Network: /etc/hosts entries should be <= 2 (use DNS). Actual: $entries"
        if [ "$entries" -le 2 ]; then
            local rc=0
            while read -r line; do
                entry=$(echo "$line" | grep -Ev "^#|^ *$")
                if [ ! "$entry" = "" ]; then
                    # the following line ('set -- $(...)') can't be quoted
                    # shellcheck disable=SC2046
                    set -- $(echo "$line" | awk '{ print $1, $2 }')
                    if [ "$1" = "127.0.0.1" ] || [ "$1" = "::1" ] && [ "$2" = "localhost" ]; then
                        :
                    else
                        rc=1
                    fi
                fi
            done < /etc/hosts
            if [ "$rc" -eq 0 ]; then
                state "$msg" 0
            else
                state "${msg}, but has non localhost" 2
            fi
        else
            state "$msg" 2
        fi
    }

    function check_nscd_and_sssd() {
        _check_service_is_running 'Network' 'nscd'
        local nscd_running=${SERVICE_STATE['running']}
        _check_service_is_running 'Network' 'sssd' 2
        local sssd_running=${SERVICE_STATE['running']}

        if $nscd_running && $sssd_running; then
            # 7.8. USING NSCD WITH SSSD
            # SSSD is not designed to be used with the NSCD daemon.
            # Even though SSSD does not directly conflict with NSCD, using both services
            # can result in unexpected behavior, especially with how long entries are cached.
            # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/System-Level_Authentication_Guide/usingnscd-sssd.html

            # How-to: Deploy Apache Hadoop Clusters Like a Boss
            # Name Service Caching
            # If you’re running Red Hat SSSD, you’ll need to modify the nscd configuration;
            # with SSSD enabled, don’t use nscd to cache passwd, group, or netgroup information.
            # http://blog.cloudera.com/blog/2015/01/how-to-deploy-apache-hadoop-clusters-like-a-boss/
            # shellcheck disable=SC2013
            for cached in $(awk '/^[^#]*enable-cache.*yes/ { print $2 }' /etc/nscd.conf); do
                case $cached in
                    'passwd'|'group'|'netgroup')
                        state "Network: nscd should not cache $cached with sssd enabled" 1
                        ;;
                    *)
                        ;;
                esac
            done
            # shellcheck disable=SC2013
            for non_cached in $(awk '/^[^#]*enable-cache.*no/ { print $2 }' /etc/nscd.conf); do
                case $non_cached in
                    'passwd'|'group'|'netgroup')
                        state "Network: nscd shoud not cache $non_cached with sssd enabled" 0
                        ;;
                    *)
                        ;;
                esac
            done
        fi
    }

    # Consistency check on forward (hostname to ip address) and
    # reverse (ip address to hostname) resolutions.
    # Note that an additional `.' in the PTR ANSWER SECTION.
    function check_dns() {
        which dig 2&>/dev/null
        if [ $? -eq 2 ]; then
            state "Network: 'dig' not found, skipping DNS checks. Run 'sudo yum install bind-utils' to fix." 2
            return
        fi

        local fqdn
        local fwd_lookup
        local rvs_lookup
        fqdn=$(hostname -f)
        fwd_lookup=$(dig -4 "$fqdn" A +short)
        rvs_lookup=$(dig -4 -x "$fwd_lookup" PTR +short)
        if [[ "${fqdn}." = "$rvs_lookup" ]]; then
            state "Network: Consistent name resolution of $fqdn" 0
        else
            state "Network: Inconsistent name resolution of $fqdn. Check DNS configuration" 1
        fi
    }
    check_ipv6
    check_hostname
    check_etc_hosts
    check_nscd_and_sssd
    check_dns
)

function check_firewall() {
    # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/install_cdh_disable_iptables.html
    if is_centos_rhel_7; then
        _check_service_is_not_running 'Network' 'firewalld'
    else
        _check_service_is_not_running 'Network' 'iptables'
    fi
}

function checks() (
    print_header "Prerequisite checks"
    reset_service_state
    check_os
    check_network
    check_firewall
    check_java
    check_database
    check_jdbc_connector
)
