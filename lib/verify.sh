#!/bin/bash

PWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TMP=$PWD/tmp
mkdir -p $TMP
rm -f $TMP/*

function scusage() {
	cat <<-EOS
		Usage:       ./verify.sh <DOMAIN>
		Example:     ./verify.sh AD.CLOUDERA.COM
	EOS
	exit 1
}

if [ $# -ne 1 ]; then
	scusage
else
	DOMAIN=$1
fi

if  [ -f $PWD/cldap.pl ]
then
	dig -t SRV _kerberos_tcp.$DOMAIN > $TMP/dig1.tmp
	AC=`cat $TMP/dig1.tmp | grep "AUTHORITY: 1" | wc -l`
	if [ $AC -eq "1" ]
	then
		AUTH=`cat $TMP/dig1.tmp | grep -A1 "AUTHORITY SECTION:" | tail -n 1`
		SOAQ=`echo $AUTH | grep SOA | wc -l`
		if [ $SOAQ -eq "1" ]
		then
			DC=`echo $AUTH | awk '{print $5}' | sed 's/.$//'`
			$PWD/cldap.pl $DOMAIN -s $DC > $TMP/dc.tmp
			SITEN=`cat $TMP/dc.tmp | grep --text "Server Site Name:" | awk '{print $NF}'`
			dig @$DC -t SRV _ldap._tcp.$SITEN._sites.dc._msdcs.$DOMAIN > $TMP/dig2.tmp

			echo -e "AD Domain\t\t\t: $DOMAIN"
			echo -e "Authoritative Domain Controller\t: $DC"
			echo -e "Site Name\t\t\t: $SITEN"
			echo -e "-----------------------------------------------------------------------------"
			echo -e "# _service._proto.name.\t\tTTL\tclass\tSRV\tpriority\tweight\tport\ttarget."
			cat $TMP/dig2.tmp | grep -A 100 "ANSWER SECTION" | grep -B 100 "Query time" | sed '1d' | sed '$d'
		fi
	else
		echo "DOMAIN NOT FOUND"
	fi
else
	echo "cldap.pl missing. Download it and then rerun"
fi
