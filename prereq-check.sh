#!/usr/bin/env bash

set -e

# TODO auto-merge into one file
. lib/utils.sh
. lib/checks.sh
. lib/info.sh

SYSINFO_TITLE_WIDTH=20

function system_info() {
  print_header "System information"
  print_fqdn
  print_distro
  print_kernel
  print_cpu
  print_ram
  print_disks
  print_free_space
  print_cloudera_rpms
  print_time
  print_network
  echo
}

function checks() {
  print_header "Prerequisite checks"
  check_os
  check_network
  check_java
  check_database
  echo
}

if [ `uname` = 'Darwin' ]; then
  echo "Mac OS is not supported. Linux only."
  exit 1
fi

# Cache `rpm -qa` since it's slow and we call it several times
RPM_QA=`rpm -qa | sort`

# TODO check hostname
# TODO check fs + reserved space
# TODO check iptables + routes
# TODO check timezone
# TODO check NTP
# TODO check ulimits
# TODO check THP
# TODO check JDBC connector
# TODO check cloudera manager and agent versions
# TODO check nscd

system_info
checks
echo "Done!"
