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

function check_java() {
  # The following candidate list is stolen from CM agent
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

  local JAVA_HOME_CANDIDATES=(${JAVA7_HOME_CANDIDATES[@]}
                              ${JAVA8_HOME_CANDIDATES[@]}
                              ${JAVA6_HOME_CANDIDATES[@]}
                              ${MISCJAVA_HOME_CANDIDATES[@]}
                              ${OPENJAVA7_HOME_CANDIDATES[@]}
                              ${OPENJAVA8_HOME_CANDIDATES[@]}
                              ${OPENJAVA6_HOME_CANDIDATES[@]})

  # attempt to find and verify java
  #
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
      _check_service_is_running     'System' 'chronyd'
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
}

function check_database() {
  local mysql=`echo "$RPM_QA" | egrep -v "mysql-community-(common|libs|client)-" | egrep -v "mysql-(common|libs|client)-" | grep -m1 "^mysql-"`
  if [ "$mysql" ]; then
    local ver=`echo $mysql | cut -d'-' -f1-4`
  else
    state "Database: MySQL server not installed, skipping version check" 2
    return
  fi

  local major_ver=`echo $ver | cut -d'-' -f4 | cut -d'.' -f1-2`
  local msg="Database: Supported MySQL server installed. Actual: $ver"
  if [ "$major_ver" = "5.5" ] || [ "$major_ver" = "5.6" ]; then
    state "$msg" 0
  else
    state "$msg" 1
  fi
}

function check_jdbc_connector() {
  local connector=/usr/share/java/mysql-connector-java.jar
  if [ -f $connector ]; then
    state "Database: MySQL connector is installed" 0
  else
    state "Database: MySQL connector is not installed" 2
  fi
}

function check_network() {
  if [ `ping -W1 -c1 8.8.8.8 &>/dev/null; echo $?` -eq 0 ]; then
    state "Network: Has Internet connection" 0
  else
    state "Network: No Internet connection" 2
  fi

  check_hostname

  local entries=`cat /etc/hosts | egrep -v "^#|^ *$" | wc -l`
  local msg="Network: /etc/hosts entries should be <= 2 (use DNS). Actual: $entries"
  if [ "$entries" -le 2 ]; then
    local rc=0
    while read line; do
      entry=`echo $line | egrep -v "^#|^ *$"`
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
    _check_service_is_not_autostart 'Network' 'firewalld'
  else
    _check_service_is_not_running 'Network' 'iptables'
    _check_service_is_not_autostart 'Nerwork' 'iptables'
  fi
  _check_service_is_running     'Network' 'nscd'
  _check_service_is_not_running 'Network' 'sssd'

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
  sudo `service_cmd` &>/dev/null
  case $? in
    0) state "$prefix: $service is running"       0;;
    3) state "$prefix: $service is not running"   1;;
    *) state "$prefix: $service is not installed" 1;;
  esac

  if is_centos_rhel_7; then
    if [ "`systemctl is-enabled $service 2>/dev/null`" == "enabled" ]; then
      state "$prefix: $service auto-starts on boot" 0
    else
      state "$prefix: $service does not auto-start on boot" 1
    fi
  else
    local chkconfig=`chkconfig 2>/dev/null | awk "/^$service / {print \\$5}"`
    [ "$chkconfig" ] || chkconfig=""
    if [ "$chkconfig" = "3:on" ]; then
      state "$prefix: $service auto-starts on boot" 0
    else
      state "$prefix: $service does not auto-start on boot" 1
    fi
  fi
}

function _check_service_is_not_running() {
  local prefix=$1
  local service=$2
  if is_centos_rhel_7; then
    local sub_state=`systemctl show $service --type=service --property=SubState | sed -e 's/^.*=//'`
    if [[ $sub_state = 'running' ]]; then
      state "$prefix: $service should not running" 1
    else
      state "$prefix: $service is not running" 0
    fi
  else
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
  fi
}

function _check_service_is_not_autostart() {
  local prefix=$1
  local service=$2
  if is_centos_rhel_7; then
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

function check_hostname() {
  local fqdn=`hostname -f`
  local short=`hostname -s`

  # https://en.wikipedia.org/wiki/Hostname
  # Hostnames are composed of series of labels concatenated with dots, as are
  # all domain names. Each label must be from 1 to 63 characters long, and the
  # entire hostname (including delimiting dots but not a trailing dot) has a
  # maximum of 253 ASCII characters.
  echo $fqdn | egrep -iq '^([a-z0-9][a-z0-9\-]{1,61}[a-z0-9]\.)+[a-z]+$'
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

function is_centos_rhel_7() {
  if [ -f /etc/redhat-release ] && grep -q " 7." /etc/redhat-release; then
    return 0;
  else
    return 1;
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

#
# Code previously reside in verify.sh
#
function check_security() {
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
