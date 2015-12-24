function print_label() {
  printf "%-${SYSINFO_TITLE_WIDTH}s %s\n" "$1:" "$2"
}

function print_time() {
  local timezone=`ls -lh /etc/localtime | cut -d' ' -f11 | cut -d'/' -f5-`
  print_label "Timezone" "$timezone"
  print_label "DateTime" "`date`"
}

function print_fqdn() {
  print_label "FQDN" `hostname -f`
}

function print_distro() {
  local distro="Unknown"
  if [ -f /etc/redhat-release ]; then
    distro=`sed -e 's/release //' -e 's/ (Final)//' /etc/redhat-release`
  fi
  print_label "Distro" "$distro"
}

function print_kernel() {
  print_label "Kernel" `uname -r`
}

function print_cpu() {
  local cpu=`grep -m1 "^model name" /proc/cpuinfo | cut -d' ' -f3- | sed -e 's/(R)//' -e 's/Core(TM) //' -e 's/CPU //'`
  print_label "CPUs" "`nproc`x $cpu"
}

function print_ram() {
  local ram_kb=`grep "MemTotal:" /proc/meminfo | cut -d' ' -f8`
  print_label "RAM" "`echo $ram_kb/1000/1000 | bc` GB"
}

function print_disks() {
  echo "Disks:"
  for d in /dev/sd?; do
    pad; echo -n "$d  "
    fdisk -l $d | grep "^Disk /dev/sd" | cut -d' ' -f3-4 | cut -d',' -f1
  done
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
  local hosts=`grep "^hosts:" /etc/nsswitch.conf | sed 's/^hosts: *//'`
  print_label "nsswitch" "$hosts"
}
