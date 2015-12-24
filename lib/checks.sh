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
    state "Java: No Oracle Java installed" 1
  fi

  local java=`echo "$RPM_QA" | grep "^java-"`
  if [ "$java" ]; then
    #local ver=`echo $java | cut -d'-' -f1-4`
    state "Java: Multiple Java versions installed:" 1
    for j in `echo "$java"`; do
      echo "       - $j"
    done
  else
    state "Java: No other Java versions installed" 0
  fi
}

function check_os() {
  local swappiness=`cat /proc/sys/vm/swappiness`
  local msg="System: /proc/sys/vm/swappiness should be = 1"
  if [ "$swappiness" -eq 1 ]; then
    state "$msg" 0
  else
    state "$msg. Actual: $swappiness" 1
  fi
}

function check_database() {
  # MySQL
  local mysql=`echo "$RPM_QA" | egrep -v "mysql-community-(common|libs|client)-" | egrep "^mysql-.*-server|^mysql-" | tail -1`
  if [ "$mysql" ]; then
    local ver=`echo $mysql | cut -d'-' -f1-4`
  else
    state "Database: MySQL server not found, skipping version check" 2
    return
  fi
  local major_ver=`echo $ver | cut -d'-' -f4 | cut -d'.' -f1-2`
  local msg="Database: MySQL server should be v5.5 or v5.6. Actual: $ver"
  if [ "$major_ver" = "5.5" ] || [ "$major_ver" = "5.6" ]; then
    state "$msg" 0
  else
    state "$msg" 1
  fi
}

function check_network() {
  if [ `ping -W1 -c1 8.8.8.8 &>/dev/null; echo $?` -eq 0 ]; then
    state "Network: Has Internet connection" 0
  else
    state "Network: No Internet connection" 2
  fi

  local hosts=`grep "^hosts:" /etc/nsswitch.conf | sed 's/^hosts: *//'`
  # print_label "nsswitch" "$hosts"

  local entries=`cat /etc/hosts | egrep -v "^#|^ *$" | wc -l`
  local msg="Network: /etc/hosts entries should be <= 2 (use DNS). Actual: $entries"
  if [ "$entries" -le 2 ]; then
    state "$msg" 0
  else
    state "$msg" 2
  fi
}
