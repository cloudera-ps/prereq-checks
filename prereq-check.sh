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

# Include libs (START) --------------------------------------------------------
# Do not remove the place marker "Include libs (START|STOP)" comments. They are
# place markers for generating the single file script.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. "$DIR/lib/utils.sh"
. "$DIR/lib/checks.sh"
. "$DIR/lib/info.sh"
# Include libs (STOP)  --------------------------------------------------------

BANNER="Cloudera Manager & CDH Prerequisites Checks v$VER"

if [ `uname` = 'Darwin' ]; then
    echo -e "\nThis tool runs on Linux only, not Mac OS."
    exit 1
fi

function usage() {
    SCRIPTNAME=$(basename $BASH_SOURCE)
    echo "`tput bold`NAME:`tput sgr0`"
    echo "  ${SCRIPTNAME} - ${BANNER}"
    echo
    echo "`tput bold`SYNOPSIS:`tput sgr0`"
    echo "  ${SCRIPTNAME} [options]"
    echo
    echo "`tput bold`OPTIONS:`tput sgr0`"
    echo "  -h, --help"
    echo "    Show this message"
    echo
    echo "  -a, --addc `tput smul`domain`tput sgr0`"
    echo "    Run tests against Active Directory Domain Controller"
    echo
    echo "  -p, --privilegetest `tput smul`ldapURI`tput sgr0` `tput smul`binddn`tput sgr0` `tput smul`searchbase`tput sgr0` `tput smul`bind_user_password`tput sgr0`"
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
        check_addc ${ARG_DOMAIN}
    fi
elif [[ ${OPT_USER} ]]; then
    if [[ -z ${ARG_LDAPURI} || -z ${ARG_BINDDN} || -z ${ARG_SEARCHBASE} || -z ${ARG_USERPSWD} ]]; then
        >&2 echo "Options missing"
        usage
    else
        check_privs ${ARG_LDAPURI} ${ARG_BINDDN} ${ARG_SEARCHBASE}
    fi
else
    echo ${BANNER}

    # Cache `rpm -qa` since it's slow and we call it several times
    RPM_QA=`rpm -qa | sort`

    system_info
    checks
    echo
fi

