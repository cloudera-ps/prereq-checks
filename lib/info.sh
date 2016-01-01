SYSINFO_TITLE_WIDTH=14

function print_label() {
  printf "%-${SYSINFO_TITLE_WIDTH}s %s\n" "$1:" "$2"
}

function print_time() {
  local timezone=`ls -lh /etc/localtime | cut -d' ' -f11 | cut -d'/' -f5-`
  timezone="${timezone:-UTC}"
  print_label "Timezone" "$timezone"
  print_label "DateTime" "`date`"
}

function print_fqdn() {
  print_label "FQDN" `hostname -f`
}

function print_os() {
  local distro="Unknown"
  if [ -f /etc/redhat-release ]; then
    distro=`sed -e 's/release //' -e 's/ (Final)//' /etc/redhat-release`
  fi
  print_label "Distro" "$distro"
  print_label "Kernel" `uname -r`
}

function print_cpu_and_ram() {
  local cpu=`grep -m1 "^model name" /proc/cpuinfo | cut -d' ' -f3- | sed -e 's/(R)//' -e 's/Core(TM) //' -e 's/CPU //'`
  print_label "CPUs" "`nproc`x $cpu"
  print_label "RAM" "`awk '/MemTotal:/ {printf "%d GB", $2/1000/1000}' /proc/meminfo`"
}

function print_disks() {
  echo "Disks:"
  for d in `ls /dev/{sd?,xvd?} 2>/dev/null`; do
    pad; echo -n "$d  "
    sudo fdisk -l $d 2>/dev/null | grep "^Disk /dev/" | cut -d' ' -f3-4 | cut -d',' -f1
  done

  local mnts=`mount | grep /data || true`
  if [ "$mnts" ]; then
    echo "Data mounts:"
    local IFS=$'\n'
    for m in `echo "$mnts"`; do
      pad; echo "$m"
    done
  else
    print_label "Data mounts" "None found"
  fi
}

function print_free_space() {
  echo "Free space:"
  free_space /opt
  free_space /var/log
}

function free_space() {
  local path=$1
  local free=`df -Ph $path | tail -1 | cut -d' ' -f7`
  pad
  printf "%-9s %s\n" $path $free
}

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
}
