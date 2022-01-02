#!/usr/bin/env bash

function check_addc() {
    # the domainname passed by the caller, already checked to be non-empty
    DOMAIN=$1
    # the directory of the script
    DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    # the temp directory used, within $DIR
    WORK_DIR=$(mktemp -d -p "${DIR}")
    # check if tmp dir was created
    if [[ ! ${WORK_DIR} || ! -d ${WORK_DIR} ]]; then
        echo "Could not create temp dir"
        exit 1
    fi

    function cleanup {
        # FIXME This is dangerous!
        rm -rf "${WORK_DIR}"
    }
    trap cleanup EXIT

    dig -t SRV "_kerberos_tcp.${DOMAIN}" > "${WORK_DIR}/dig1.tmp"
    AC=$(grep -c "AUTHORITY: 1" "${WORK_DIR}/dig1.tmp")
    if [[ ${AC} -eq "1" ]]; then
        AUTH=$(grep -A1 "AUTHORITY SECTION:" "${WORK_DIR}/dig1.tmp" | tail -n 1)
        SOAQ=$(echo "${AUTH}" | grep -c SOA)
        if [[ ${SOAQ} -eq "1" ]]; then
            DC=$(echo "${AUTH}" | awk '{print $5}' | sed 's/.$//')
            perl /tmp/prereq-checks-cldap.pl "${DOMAIN}" -s "${DC}" > "${WORK_DIR}/dc.tmp"
            SITEN=$(grep --text "Server Site Name:" "${WORK_DIR}/dc.tmp" | awk '{print $NF}')
            dig "@${DC}" -t SRV "_ldap._tcp.${SITEN}._sites.dc._msdcs.${DOMAIN}" > "${WORK_DIR}/dig2.tmp"

            echo -e "AD Domain\t\t\t: ${DOMAIN}"
            echo -e "Authoritative Domain Controller\t: ${DC}"
            echo -e "Site Name\t\t\t: ${SITEN}"
            echo -e "-----------------------------------------------------------------------------"
            echo -e "# _service._proto.name.\t\tTTL\tclass\tSRV\tpriority\tweight\tport\ttarget."
            grep -A 100 "ANSWER SECTION" "${WORK_DIR}/dig2.tmp" | grep -B 100 "Query time" | sed '1d' | sed '$d'
        fi
    else
        echo "DOMAIN NOT FOUND"
    fi
}

function check_privs() {
    print_header "Prerequisite checks: Direct to AD integration:"
    ldapsearch -x -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" -b "${ARG_SEARCHBASE}"  -L -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero
    SRCH_RESULT=$?
    if [ $SRCH_RESULT -eq 0 ]; then
        state "KDC Account Manager user exists" 0
        cat > /tmp/prereq-check.ldif <<EOFILE
dn: CN=Cloudera User,${ARG_SEARCHBASE}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
EOFILE
        # NOTE: Heredoc requires the above spacing/format or it won't work.
        ldapadd -x -H "${ARG_LDAPURI}" -a -D "${ARG_BINDDN}" -f /tmp/prereq-check.ldif -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero

        ADD_RESULT=$?
        if [ $ADD_RESULT -eq 0 ]; then
            state "Has delegated privileges to add a new user on the OU" 0
            ldapdelete -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" "CN=Cloudera User,${ARG_SEARCHBASE}" -w "${ARG_USERPSWD}"
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
    elif [ $SRCH_RESULT -eq 32 ]; then
        state "Unable to find OU" 1
    elif [ $SRCH_RESULT -eq 49 ]; then
        state "Invalid KDC Account Manager credentials" 1
    elif [ $SRCH_RESULT -eq 255 ]; then
        state "Not able to find the LDAP server specified" 1
    elif [ $SRCH_RESULT -eq 34 ]; then
        state "Invalid OU DN" 1
    else
        state -e "Unrecognized error occured. Not able to connect to AD using\n\tLDAPURI: ${ARG_LDAPURI}\n\tBINDDN: ${ARG_BINDDN}\n\tSEARCHBASE: ${ARG_SEARCHBASE}\n\tand provided password" 1
    fi
}
