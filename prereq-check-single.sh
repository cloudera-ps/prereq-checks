#!/usr/bin/env bash

# =====================================================
# prereq-check.sh: Cloudera Manager & CDH prereq check
# =====================================================
#
# Copyright 2015-2017 Cloudera, Inc.
#
# Display relevant system information and run installation prerequisite checks
# for Cloudera Manager & CDH. For details, see README.md and
# http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/installation_reqts.html.
#
# DISCLAIMER
#
# Please note: This script is released for use "AS IS" without any warranties
# of any kind, including, but not limited to their installation, use, or
# performance. We disclaim any and all warranties, either express or implied,
# including but not limited to any warranty of noninfringement,
# merchantability, and/ or fitness for a particular purpose. We do not warrant
# that the technology will meet your requirements, that the operation thereof
# will be uninterrupted or error-free, or that any errors will be corrected.
#
# Any use of these scripts and tools is at your own risk. There is no guarantee
# that they have been through thorough testing in a comparable environment and
# we are not responsible for any damage or data loss incurred with their use.
#
# You are responsible for reviewing and testing any scripts you run thoroughly
# before use in any non-testing environment.

VER=1.3.0

# Latest version at:
#   https://raw.githubusercontent.com/cloudera-ps/prereq-checks/master/prereq-check-single.sh

# security-checks.sh ------------------------------------------------
function check_addc() {
    # the domainname passed by the caller, already checked to be non-empty
    DOMAIN=$1
    # the directory of the script
    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    # the temp directory used, within $DIR
    WORK_DIR=`mktemp -d -p ${DIR}`
    # check if tmp dir was created
    if [[ ! ${WORK_DIR} || ! -d ${WORK_DIR} ]]; then
        echo "Could not create temp dir"
        exit 1
    fi
    # deletes the temp directory
    function cleanup {
        rm -rf ${WORK_DIR}
    }
    # register the cleanup function to be called on the EXIT signal
    trap cleanup EXIT
    #
    # implementation of script starts here
    #
    # cldap.dl is distributed by the Samba Team
    # https://github.com/samba-team/samba/blob/master/examples/misc/cldap.pl
    if [[ ! -f ${DIR}/cldap.pl ]]; then
        >&2 echo "cldap.pl missing. Install it under ${DIR} directory and re-run"
        exit 1
    elif [[ ! -x ${DIR}/cldap.pl ]]; then
        >&2 echo "cldap.pl is not executable. chmod +x on that script and re-run"
        exit 1
    else
        dig -t SRV _kerberos_tcp.${DOMAIN} > ${WORK_DIR}/dig1.tmp
        AC=`cat ${WORK_DIR}/dig1.tmp | grep "AUTHORITY: 1" | wc -l`
        if [[ ${AC} -eq "1" ]]; then
            AUTH=`cat ${WORK_DIR}/dig1.tmp | grep -A1 "AUTHORITY SECTION:" | tail -n 1`
            SOAQ=`echo ${AUTH} | grep SOA | wc -l`
            if [[ ${SOAQ} -eq "1" ]]; then
                DC=`echo ${AUTH} | awk '{print $5}' | sed 's/.$//'`
                ${DIR}/cldap.pl ${DOMAIN} -s ${DC} > ${WORK_DIR}/dc.tmp
                SITEN=`cat ${WORK_DIR}/dc.tmp | grep --text "Server Site Name:" | awk '{print $NF}'`
                dig @${DC} -t SRV _ldap._tcp.${SITEN}._sites.dc._msdcs.${DOMAIN} > ${WORK_DIR}/dig2.tmp

                echo -e "AD Domain\t\t\t: ${DOMAIN}"
                echo -e "Authoritative Domain Controller\t: ${DC}"
                echo -e "Site Name\t\t\t: ${SITEN}"
                echo -e "-----------------------------------------------------------------------------"
                echo -e "# _service._proto.name.\t\tTTL\tclass\tSRV\tpriority\tweight\tport\ttarget."
                cat ${WORK_DIR}/dig2.tmp | grep -A 100 "ANSWER SECTION" | grep -B 100 "Query time" | sed '1d' | sed '$d'
            fi
        else
            echo "DOMAIN NOT FOUND"
        fi
    fi
}

function check_privs() {
    print_header "Prerequisite checks: Direct to AD integration:"
    ldapsearch -x -H ${ARG_LDAPURI} -D ${ARG_BINDDN} -b "${ARG_SEARCHBASE}"  -L -w ${ARG_USERPSWD} > /dev/zero 2>/dev/zero
    SRCH_RESULT=$?
    if [ $SRCH_RESULT -eq 0 ]; then
        state "User exists" 0
        cat > /tmp/prereq-check.ldif <<EOFILE
dn: CN=Cloudera User,${ARG_SEARCHBASE}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
EOFILE
        # NOTE: Heredoc requires the above spacing/format or it won't work.

        ldapadd -x -H ${ARG_LDAPURI} -a -D ${ARG_BINDDN} -f /tmp/prereq-check.ldif -w ${ARG_USERPSWD} > /dev/zero 2>/dev/zero
        ADD_RESULT=$?
        if [ $ADD_RESULT -eq 0 ]; then
            state "Has delegated privileges to add a new user on the OU" 0
            ldapdelete -H ${ARG_LDAPURI} -D ${ARG_BINDDN} "CN=Cloudera User,${ARG_SEARCHBASE}" -w ${ARG_USERPSWD}
            DEL_RESULT=$?
            if [ $DEL_RESULT -eq 0 ]; then
                state "Has delegated privileges to delete a user on the OU" 0
                state "Sufficient privileges available to perform a direct to AD integration" 0
            fi
        elif [ $ADD_RESULT -eq 50 ]; then
            state "ldap_add: Insufficient access (50)" 1
        elif [ $ADD_RESULT -eq 68 ]; then
            state "ldap_add: Already exists (68)" 1
        else
            state "Not able to add user" 1
        fi
    elif [ $SRCH_RESULT -eq 49 ]; then
        state "Invalid credentials - ldap_bind(49)" 1
    elif [ $SRCH_RESULT -eq 10 ]; then
        state "Possible invalid BaseDN - ldap_bind(10)" 1
    elif [ $SRCH_RESULT -eq 255 ]; then
        state "Not able to find the LDAP server specified" 1
    elif [ $SRCH_RESULT -eq 34 ]; then
        state "Invalid DN syntax (34)" 1
    else
        state -e "Unrecognized error occured. Not able to connect to AD using\n\tLDAPURI: ${ARG_LDAPURI}\n\tBINDDN: ${ARG_BINDDN}\n\tSEARCHBASE: ${ARG_SEARCHBASE}\n\tand provided password" 1
    fi
}

# checks.sh ------------------------------------------------
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
    for candidate_regex in ${JAVA_HOME_CANDIDATES[@]}; do
        for candidate in `ls -rvd ${candidate_regex}* 2>/dev/null`; do
            if [ -x ${candidate}/bin/java ]; then
                VERSION_STRING=`${candidate}/bin/java -version 2>&1`
                RE_JAVA_GOOD='java[[:space:]]version[[:space:]]\"1\.([0-9])\.0_([0-9][0-9]*)\"'
                RE_JAVA_BAD='openjdk[[:space:]]version[[:space:]]\"1\.[0-9]\.'
                if [[ $VERSION_STRING =~ $RE_JAVA_GOOD ]]; then
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
                        else
                            state "Java: Supported Oracle Java: ${candidate}/bin/java" 0
                        fi
                    else
                        state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 0
                    fi
                elif [[ $VERSION_STRING =~ $_RE_JAVA_BAD ]]; then
                    state "Java: Unsupported OpenJDK: ${candidate}/bin/java" 1
                else
                    state "Java: Unsupported Unknown: ${candidate}/bin/java" 1
                fi
            fi
        done
    done
}

function check_os() {
    # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__section_xpq_sdf_jq
    local swappiness=`cat /proc/sys/vm/swappiness`
    local msg="System: /proc/sys/vm/swappiness should be 1"
    if [ "$swappiness" -eq 1 ]; then
        state "$msg" 0
    else
        state "$msg. Actual: $swappiness" 1
    fi

    # "tuned" service should be disabled on RHEL/CentOS 7.x
    # https://www.cloudera.com/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__disable-tuned
    if is_centos_rhel_7; then
        systemctl status tuned &>/dev/null
        case $? in
            0) state "System: tuned is running" 1;;
            3) state "System: tuned is not running" 0;;
            *) state "System: tuned is not installed" 0;;
        esac
        if [ "`systemctl is-enabled tuned 2>/dev/null`" == "enabled" ]; then
            state "System: tuned auto-starts on boot" 1
        else
            state "System: tuned does not auto-start on boot" 0
        fi
    fi

    # Older RHEL/CentOS versions use [1], while newer versions (e.g. 7.1) and
    # Ubuntu/Debian use [2]:
    #   1: /sys/kernel/mm/redhat_transparent_hugepage/defrag
    #   2: /sys/kernel/mm/transparent_hugepage/defrag.
    # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__section_hw3_sdf_jq
    local file=`find /sys/kernel/mm/ -type d -name '*transparent_hugepage'`/defrag
    if [ -f $file ]; then
        local msg="System: $file should be disabled"
        if fgrep -q "[never]" $file; then
            state "$msg" 0
        else
            state "$msg. Actual: `cat $file | awk '{print $1}' | sed -e 's/\[//' -e 's/\]//'`" 1
        fi
    else
        state "System: /sys/kernel/mm/*transparent_hugepage not found. Check skipped" 2
    fi

    # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/install_cdh_disable_selinux.html
    local msg="System: SELinux should be disabled"
    case `getenforce` in
        Disabled|Permissive) state "$msg" 0;;
        *)                   state "$msg. Actual: `getenforce`" 1;;
    esac

    if is_centos_rhel_7; then
        ntpd_used="$(_validate_service_state 'System' 'ntpd')"
        if [ $ntpd_used -eq 0 ]; then
            _check_service_is_running 'System' 'ntpd'
            is_ntp_in_sync
        else
            # Add check to see if chrony is actually synchronizing the clock. Use the command "chronyc tracking"
            _check_service_is_running 'System' 'chronyd'
        fi
    else
        _check_service_is_running 'System' 'ntpd'
        is_ntp_in_sync
    fi

    local packages_32bit=`rpm -qa --queryformat '\t%{NAME} %{ARCH}\n' | grep 'i[6543]86' | cut -d' ' -f1`
    if [ "$packages_32bit" ]; then
        state "System: Found the following 32bit packages installed:\n$packages_32bit" 1
    else
        state "System: Only 64bit packages should be installed" 0
    fi

    local UNNECESSARY_SERVICES=(
        'bluetooth'
        'cups'
        'iptables'
        'ip6tables'
        'postfix'
    )
    for svc in ${UNNECESSARY_SERVICES[@]}; do
        _check_service_is_running 'DUMMY' ${svc} > /dev/null
        local svc_running=${SERVICE_STATUS['running']}
        if $svc_running; then
            state "System: $svc is running (not recommended)" 2
        else
            state "System: $svc is not running (recommended)" 0
        fi
    done

    local noexec=false
    for option in `findmnt -lno options --target /tmp | tr ',' ' '`; do
        if [[ $option = 'noexec' ]]; then
            noexec=true
        fi
    done
    if $noexec; then
        state "System: /tmp mounted with noexec fails for CM versions older than 5.8.4, 5.9.2, and 5.10.0" 2
    else
        state "System: /tmp mounted with noexec fails for CM versions older than 5.8.4, 5.9.2, and 5.10.0" 0
    fi
}

function check_database() {
    local VERSION_PATTERN='([0-9][0-9]*\.[0-9][0-9]*)\.[0-9][0-9]*'
    local mysql_ver=''
    local mysql_rpm=''
    local mysql_ent=`rpm -q --queryformat='%{VERSION}' mysql-commercial-server`
    if [[ $? -eq 0 ]]; then
        mysql_rpm=`rpm -q mysql-commercial-server`
        [[ $mysql_ent =~ $VERSION_PATTERN ]]
        mysql_ver=${BASH_REMATCH[1]}
    fi
    local mysql_com=`rpm -q --queryformat='%{VERSION}' mysql-community-server`
    if [[ $? -eq 0 ]]; then
        mysql_rpm=`rpm -q mysql-community-server`
        [[ $mysql_com =~ $VERSION_PATTERN ]]
        mysql_ver=${BASH_REMATCH[1]}
    fi
    if [[ -z $mysql_ver ]]; then
        state "Database: MySQL server not installed, skipping version check" 2
        return
    fi

    case $mysql_ver in
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

SERVICE_STATUS=()

function check_network() {
    check_hostname

    local entries=`cat /etc/hosts | grep -Ev "^#|^ *$" | wc -l`
    local msg="Network: /etc/hosts entries should be <= 2 (use DNS). Actual: $entries"
    if [ "$entries" -le 2 ]; then
        local rc=0
        while read line; do
            entry=`echo $line | grep -Ev "^#|^ *$"`
            if [ ! "$entry" = "" ]; then
                set -- `echo $line | awk '{ print $1, $2 }'`
                if [ "$1" = "127.0.0.1" -o "$1" = "::1" ] && [ "$2" = "localhost" ]; then
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

    # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/install_cdh_disable_iptables.html
    if is_centos_rhel_7; then
        _check_service_is_not_running 'Network' 'firewalld'
    else
        _check_service_is_not_running 'Network' 'iptables'
    fi
    _check_service_is_running 'Network' 'nscd'
    local nscd_running=${SERVICE_STATUS['running']}
    _check_service_is_running 'Network' 'sssd' 2
    local sssd_running=${SERVICE_STATUS['running']}

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
        for cached in `awk '/^[^#]*enable-cache.*yes/ { print $2 }' /etc/nscd.conf`; do
            case $cached in
                'passwd'|'group'|'netgroup')
                    state "Network: nscd should not cache $cached with sssd enabled" 1
                    ;;
                *)
                    ;;
            esac
        done
        for non_cached in `awk '/^[^#]*enable-cache.*no/ { print $2 }' /etc/nscd.conf`; do
            case $non_cached in
                'passwd'|'group'|'netgroup')
                    state "Network: nscd shoud not cache $non_cached with sssd enabled" 0
                    ;;
                *)
                    ;;
            esac
        done
    fi

    # Networking Protocols Support
    # CDH requires IPv4. IPv6 is not supported and must be disabled.
    # https://www.cloudera.com/documentation/enterprise/release-notes/topics/rn_consolidated_pcm.html
    local msg="Network: IPv6 is not supported and must be disabled"
    if [[ -z `ip addr show | grep inet6` ]]; then
        state "${msg}" 0
    else
        state "${msg}" 1
    fi

    # Consistency check on forward (hostname to ip address) and
    # reverse (ip address to hostname) resolutions.
    # Note that an additional `.' in the PTR ANSWER SECTION.
    local fqdn=`hostname -f`
    local fwd_lookup=`dig -4 $fqdn A +short`
    local rvs_lookup=`dig -4 -x $fwd_lookup PTR +short`
    local msg="Network: Consistent name resolution of $fqdn"
    if [[ "${fqdn}." = $rvs_lookup ]]; then
        state "${msg}" 0
    else
        state "${msg}" 1
    fi
}

function check_hostname() {
    local fqdn=`hostname -f`
    local short=`hostname -s`

    # https://en.wikipedia.org/wiki/Hostname
    # Hostnames are composed of series of labels concatenated with dots, as are
    # all domain names. Each label must be from 1 to 63 characters long, and the
    # entire hostname (including delimiting dots but not a trailing dot) has a
    # maximum of 253 ASCII characters.
    local VALID_FQDN='^([a-z]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9\-]{0,61}[a-z0-9])?$'
    echo $fqdn | grep -Eiq $VALID_FQDN
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
            if [[ `echo $fqdn | sed -e 's/\..*//'` = $short ]]; then
                if [[ `echo $fqdn | grep '[A-Z]'` = "" ]]; then
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

function is_ntp_in_sync() {
    if [ `ntpstat | grep "synchronised to NTP server" | wc -l` -eq 1 ]; then
        state "System: Clock is synchronized against the NTPD server" 0
    else
        state "System: NTP is not synchronized. Check ntpstat to troubleshoot" 1
    fi
}

function check_only_64bit_packages_installed() {
    local packages_32bit=`rpm -qa --queryformat '\t%{NAME} %{ARCH}\n' | grep 'i[6543]86' | cut -d' ' -f1`
    if [ "$packages_32bit" ]; then
        state "Only 64bit packages: 32bit packages are installed:\n$packages_32bit" 1
    else
        state "Only 64bit packages: Only 64bit packages are installed" 0
    fi
}

function checks() {
    print_header "Prerequisite checks"
    check_os
    check_network
    check_java
    check_database
    check_jdbc_connector
}

# info.sh ------------------------------------------------
function print_time() {
    local timezone=`date | awk '{print $(NF-1)}'`
    timezone=${timezone:-UTC}
    print_label "Timezone" "$timezone"
    print_label "DateTime" "`date`"
}

function print_fqdn() {
    print_label "FQDN" `hostname -f`
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
    print_label "Kernel" `uname -r`
}

function print_cpu_and_ram() {
    local cpu=`grep -m1 "^model name" /proc/cpuinfo | cut -d' ' -f3- | sed -e 's/(R)//' -e 's/Core(TM) //' -e 's/CPU //'`
    print_label "CPUs" "`nproc`x $cpu"
    # Total installed memory (MemTotal and SwapTotal in /proc/meminfo)
    print_label "RAM" "$(awk '/^MemTotal:/ { printf "%.2f", $2/1024/1024 ; exit}' /proc/meminfo)G"
}

function print_disks() (
    function data_mounts() {
        while read source target fstype options; do
            local NOATIME=false
            for option in `echo $options | tr ',' ' '`; do
                if [[ $option = 'noatime' ]]; then
                    NOATIME=true
                fi
            done
            echo -n "$source $target "
            case $fstype in
                'xfs')
                    local resblks=`xfs_io -xc resblks $target | awk '/^reserved blocks =/ { print $4 }'`
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
                    local resblks=`tune2fs -l $source | awk '/^Reserved block count:/ { print $4 }'`
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
    for d in `ls /dev/{sd?,xvd?} 2>/dev/null`; do
        pad; echo -n "$d  "
        sudo fdisk -l $d 2>/dev/null | grep "^Disk /dev/" | cut -d' ' -f3-4 | cut -d',' -f1
    done
    echo "Mount:"
    findmnt -lo source,target,fstype,options | grep '^/dev' | \
        while read line; do
            pad; echo $line
        done
    echo "Data mounts:"
    local DATA_MOUNTS=$( findmnt -lno source,target,fstype,options | \
        grep -E '[[:space:]]/data' | data_mounts )
    if [[ -z ${DATA_MOUNTS} ]]; then
        pad; echo "None found"
    else
        local IFS='|'
        echo ${DATA_MOUNTS} | while read line; do
            pad; echo $line
        done
    fi
)

function print_free_space() (
    function free_space() {
        # Pick "Avail" column as "Free space:"
        # $ df -Ph /opt
        # Filesystem      Size  Used Avail Use% Mounted on
        # /dev/sda1        99G  1.8G   92G   2% /
        local path=$1
        local free=`df -Ph $path | tail -1 | awk '{print $4}'`
        pad
        printf "%-9s %s\n" $path $free
    }
    echo "Free space:"
    free_space /opt
    free_space /var/log
)

function print_cloudera_rpms() {
    local rpms=`echo -e "$RPM_QA" | grep "^cloudera-"`
    if [ "$rpms" ]; then
        echo "Cloudera RPMs:"
        for line in `echo $rpms`; do
            local pkg=`echo $line | cut -d'-' -f1-3`
            local ver=`echo $line | cut -d'-' -f4-`
            pad
            printf "%-24s  %s\n" "$pkg" "$ver"
        done
    else
        echo "Cloudera RPMs: None installed"
    fi
}

function print_network() {
    print_label "nsswitch" "`grep "^hosts:" /etc/nsswitch.conf | sed 's/^hosts: *//'`"
    print_label "DNS server" `grep "^nameserver" /etc/resolv.conf | cut -d' ' -f2`
}

function print_internet() {
  if [ `ping -W1 -c1 8.8.8.8 &>/dev/null; echo $?` -eq 0 ]; then
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
    print_disks
    print_free_space
    print_cloudera_rpms
    print_time
    print_network
    print_internet
}

# utils.sh ------------------------------------------------
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

# prereq-check.sh (main) ------------------------------------------------

BANNER="Cloudera Manager & CDH Prerequisites Checks v$VER"

if [ "$(uname)" = 'Darwin' ]; then
    echo -e "\nThis tool runs on Linux only, not Mac OS."
    exit 1
fi

function usage() {
    SCRIPTNAME=$(basename "${BASH_SOURCE[0]}")
    echo "$(tput bold)NAME:$(tput sgr0)"
    echo "  ${SCRIPTNAME} - ${BANNER}"
    echo
    echo "$(tput bold)SYNOPSIS:$(tput sgr0)"
    echo "  ${SCRIPTNAME} [options]"
    echo
    echo "$(tput bold)OPTIONS:$(tput sgr0)"
    echo "  -h, --help"
    echo "    Show this message"
    echo
    echo "  -a, --addc $(tput smul)domain$(tput sgr0)"
    echo "    Run tests against Active Directory Domain Controller"
    echo
    echo "  -p, --privilegetest $(tput smul)ldapURI$(tput sgr0) $(tput smul)binddn$(tput sgr0) $(tput smul)searchbase$(tput sgr0) $(tput smul)bind_user_password$(tput sgr0)"
    echo "    Run tests against Active Directory delegated user for Direct to AD integration"
    echo "    http://blog.cloudera.com/blog/2014/07/new-in-cloudera-manager-5-1-direct-active-directory-integration-for-kerberos-authentication/"
    echo
    exit 1
}

if [[ $# -gt 0 ]]; then
    KEY=$1
    case ${KEY} in
        -h|--help)
            OPT_USAGE=true
            ;;
        -a|--addc)
            OPT_DOMAIN=true
            ARG_DOMAIN=$2
            ;;
        -p|--privilegetest)
            OPT_USER=true
            ARG_LDAPURI=$2
            ARG_BINDDN=$3
            ARG_SEARCHBASE=$4
            ARG_USERPSWD=$5
            ;;
        *)
            # Unknown option
            OPT_USAGE=true
            >&2 echo "Unknown option: ${KEY}"
            ;;
    esac
fi

if [[ ${OPT_USAGE} ]]; then
    usage
elif [[ ${OPT_DOMAIN} ]]; then
    if [[ -z ${ARG_DOMAIN} ]]; then
        >&2 echo "Missing domain argument. ex) AD.CLOUDERA.COM"
        usage
    else
        check_addc "${ARG_DOMAIN}"
    fi
elif [[ ${OPT_USER} ]]; then
    if [[ -z ${ARG_LDAPURI} || -z ${ARG_BINDDN} || -z ${ARG_SEARCHBASE} || -z ${ARG_USERPSWD} ]]; then
        >&2 echo "Options missing"
        usage
    else
        check_privs "${ARG_LDAPURI}" "${ARG_BINDDN}" "${ARG_SEARCHBASE}"
    fi
else
    echo "${BANNER}"

    # Cache `rpm -qa` since it's slow and we call it several times
    export RPM_QA
    RPM_QA=$(rpm -qa | sort)

    system_info
    checks
    echo
fi
