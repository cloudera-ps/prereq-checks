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
  local java=`echo "$RPM_QA" | grep "^oracle-j2sdk"`
  if [ "$java" ]; then
    local ver=`echo $java | cut -d'-' -f1-3`
    state "Java: Oracle Java installed. Actual: $ver" 0
  else
    state "Java: Oracle Java not installed" 1
  fi

  local java=`echo "$RPM_QA" | grep "^java-"`
  if [ "$java" ]; then
    #local ver=`echo $java | cut -d'-' -f1-4`
    state "Java: Unsupported Java versions installed:" 1
    for j in `echo "$java"`; do
      echo "       - $j"
    done
  else
    state "Java: No other Java versions installed" 0
  fi
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
  else
    _check_service_is_not_running 'Network' 'iptables'
  fi 
  _check_service_is_running     'Network' 'nscd'
  _check_service_is_not_running 'Network' 'sssd'
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
  sudo `service_cmd` &>/dev/null
  case $? in
    0) state "$prefix: $service is running" 0
       if [ "$service" = "iptables" ]; then
         echo "       iptable routes:"
         sudo iptables -L | sed "s/^/         /"
       fi;;
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
      if [ "$service" = "sssd" ]; then
	state "$prefix: $service auto-starts on boot" 2
      else
	state "$prefix: $service auto-starts on boot" 1
      fi
    else
      state "$prefix: $service does not auto-start on boot" 0
    fi
  fi
}

function check_hostname() {
  local fqdn=`hostname -f`
  local shortn=`hostname -s`

  if [[ `echo $fqdn | awk -F "." '{print $1}'` -eq $shortn  &&  `echo $fqdn | awk -F "." '{print NF}'` -gt 2 && ${#shortn} -le 15 ]]; then
    state "Network: FQDN looks okay" 0
  elif [ `echo $fqdn | awk -F '.' "{print NF}"` -lt 3 ]; then
    state "Network: FQDN or /etc/hosts is misconfigured. \"hostname -f\" should return the FQDN" 1
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
  local packages_32bit=`rpm -qa --queryformat '%{NAME} %{ARCH}\n\t' | grep 'i[6543]86' | cut -d' ' -f1`
  if [ "$packages_32bit" ]; then
    state "Only 64bit packages: 32bit packages are installed:\n\t$packages_32bit" 1
  else
    state "Only 64bit packages: Only 64bit packages are installed" 0
  fi
}

function checks() {
  print_header "Prerequisite checks"
  check_os

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

  check_network
  check_java
  check_database
  check_jdbc_connector
  check_only_64bit_packages_installed
}
