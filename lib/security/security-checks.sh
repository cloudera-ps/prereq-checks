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
    print_header "AD privilege checks"
    ldapsearch -x -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" -b "${ARG_SEARCHBASE}"  -L -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero
    SRCH_RESULT=$?
    if [ $SRCH_RESULT -eq 0 ]; then
        state "KDC Account Manager user exists" 0

	RANDOM_CN=prereqchk01

	ldapmodify -x -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero <<-%EOF
dn: CN=${RANDOM_CN},${ARG_SEARCHBASE}
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
sAMAccountName: ${RANDOM_CN}
%EOF

        ADD_RESULT=$?
        if [ $ADD_RESULT -eq 0 ]; then
            state "Create a new user principal in the OU" 0
            ldapdelete -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" "CN=${RANDOM_CN},${ARG_SEARCHBASE}" -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero
            DEL_RESULT=$?
            if [ $DEL_RESULT -eq 0 ]; then
                state "Delete a user principal in the OU" 0

                # continue on to perform Active Directory SPN uniqueness check impact
                check_spn_uniqueness

	    else
		state "Delete a user principal in the OU" 1
            fi
        elif [ $ADD_RESULT -eq 50 ]; then
            state "Create a new user principal in the OU (reason: Insufficient access)" 1
        elif [ $ADD_RESULT -eq 68 ]; then
            state "Create a new user principal in the OU (reason: Already exists)" 1
        else
            state "Create a new user principal in the OU" 1
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


########################################################################################################
#### SPN uniqueness check - test if Cloudera will be affected by MS patch (KB5008382) for CVE-2021-42282
########################################################################################################

function check_spn_uniqueness() {

    RANDOM_HOSTNAME="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8 ; echo '')"
    RANDOM_CN1=prereqchk02
    ldapmodify -x -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero <<-%EOF
dn: CN=${RANDOM_CN1},${ARG_SEARCHBASE}
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
sAMAccountName: ${RANDOM_CN1}
servicePrincipalName: host/${RANDOM_HOSTNAME}@test.com
%EOF

    RANDOM_CN2=prereqchk03
    ldapmodify -x -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero <<-%EOF
dn: CN=${RANDOM_CN2},${ARG_SEARCHBASE}
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
sAMAccountName: ${RANDOM_CN2}
servicePrincipalName: HTTP/${RANDOM_HOSTNAME}@test.com
%EOF

    ADD_RESULT=$?
    if [ $ADD_RESULT -eq 0 ]; then
      # creation of HTTP SPN succeeded
      state "SPN alias uniqueness check impact (MS KB5008382 patch for CVE-2021-42282)" 0
    else
      state "SPN alias uniqueness check impact (MS KB5008382 patch for CVE-2021-42282)" 1
    fi

    ldapdelete -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" "CN=${RANDOM_CN1},${ARG_SEARCHBASE}" -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero
    ldapdelete -H "${ARG_LDAPURI}" -D "${ARG_BINDDN}" "CN=${RANDOM_CN2},${ARG_SEARCHBASE}" -w "${ARG_USERPSWD}" > /dev/zero 2>/dev/zero
}
