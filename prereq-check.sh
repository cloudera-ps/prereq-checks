#!/usr/bin/env bash

# =====================================================
# prereq-check.sh: Cloudera Manager & CDH prereq check
# =====================================================
#
# Copyright Cloudera Inc. 2015
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

set -e

VER=1.1.0

# Include libs (START) --------------------------------------------------------
# Do not remove the place marker "Include libs (START|STOP)" comments. They are
# place markers for generating the single file script.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. "$DIR/lib/utils.sh"
. "$DIR/lib/checks.sh"
. "$DIR/lib/info.sh"
# Include libs (STOP)  --------------------------------------------------------

echo "Cloudera Manager & CDH Prerequisites Checks v$VER"

if [ `uname` = 'Darwin' ]; then
  echo -e "\nThis tool runs on Linux only, not Mac OS."
  exit 1
fi

# Cache `rpm -qa` since it's slow and we call it several times
RPM_QA=`rpm -qa | sort`

system_info
checks
echo
