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
# Any use of these scripts and toxxxols is at your own risk. There is no guarantee
# that they have been through thorough testing in a comparable environment and
# we are not responsible for any damage or data loss incurred with their use.
#
# You are responsible for reviewing and testing any scripts you run thoroughly
# before use in any non-testing environment.

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -u

VER=1.4.4

if [ "$(uname)" = 'Darwin' ]; then
    echo -e "\nThis tool runs on Linux only, not Mac OS."
    exit 1
fi

function cleanup {
    rm -f /tmp/prereq-checks-cldap.pl
}
trap cleanup EXIT

# Latest version at:
#   https://raw.githubusercontent.com/cloudera-ps/prereq-checks/master/prereq-check.sh

# cldap.pl ------------------------------------------------
cat << 'EOF' > /tmp/prereq-checks-cldap.pl
#!/usr/bin/perl -w

# Copyright (C) Guenther Deschner <gd@samba.org> 2006

# From https://github.com/samba-team/samba/blob/master/examples/misc/cldap.pl

use strict;
use IO::Socket;
use Convert::ASN1 qw(:debug);
use Getopt::Long;

# TODO: timeout handling, user CLDAP query

##################################

my $server = "";
my $domain = "";
my $host   = "";

##################################

my (
	$opt_debug,
	$opt_domain,
	$opt_help,
	$opt_host,
	$opt_server,
);

my %cldap_flags = (
	ADS_PDC 		=> 0x00000001, # DC is PDC
	ADS_GC 			=> 0x00000004, # DC is a GC of forest
	ADS_LDAP		=> 0x00000008, # DC is an LDAP server
	ADS_DS			=> 0x00000010, # DC supports DS
	ADS_KDC			=> 0x00000020, # DC is running KDC
	ADS_TIMESERV		=> 0x00000040, # DC is running time services
	ADS_CLOSEST		=> 0x00000080, # DC is closest to client
	ADS_WRITABLE		=> 0x00000100, # DC has writable DS
	ADS_GOOD_TIMESERV	=> 0x00000200, # DC has hardware clock (and running time)
	ADS_NDNC		=> 0x00000400, # DomainName is non-domain NC serviced by LDAP server
);

my %cldap_samlogon_types = (
	SAMLOGON_AD_UNK_R	=> 23,
	SAMLOGON_AD_R		=> 25,
);

my $MAX_DNS_LABEL = 255 + 1;

my %cldap_netlogon_reply = (
	type 			=> 0,
	flags			=> 0x0,
	guid			=> 0,
	forest			=> undef,
	domain			=> undef,
	hostname 		=> undef,
	netbios_domain		=> undef,
	netbios_hostname	=> undef,
	unk			=> undef,
	user_name		=> undef,
	server_site_name	=> undef,
	client_site_name	=> undef,
	version			=> 0,
	lmnt_token		=> 0x0,
	lm20_token		=> 0x0,
);

sub usage {
	print "usage: $0 [--domain|-d domain] [--help] [--host|-h host] [--server|-s server]\n\n";
}

sub connect_cldap ($) {

	my $server = shift || return undef;

	return IO::Socket::INET->new(
		PeerAddr	=> $server,
		PeerPort	=> 389,
		Proto		=> 'udp',
		Type		=> SOCK_DGRAM,
		Timeout		=> 10,
	);
}

sub send_cldap_netlogon ($$$$) {

	my ($sock, $domain, $host, $ntver) = @_;

	my $asn_cldap_req = Convert::ASN1->new;

	$asn_cldap_req->prepare(q<

		SEQUENCE {
			msgid INTEGER,
			[APPLICATION 3] SEQUENCE {
				basedn OCTET STRING,
				scope ENUMERATED,
				dereference ENUMERATED,
				sizelimit INTEGER,
				timelimit INTEGER,
				attronly BOOLEAN,
				[CONTEXT 0] SEQUENCE {
					[CONTEXT 3] SEQUENCE {
						dnsdom_attr OCTET STRING,
						dnsdom_val  OCTET STRING
					}
					[CONTEXT 3] SEQUENCE {
						host_attr OCTET STRING,
						host_val  OCTET STRING
					}
					[CONTEXT 3] SEQUENCE {
						ntver_attr OCTET STRING,
						ntver_val  OCTET STRING
					}
				}
				SEQUENCE {
					netlogon OCTET STRING
				}
			}
		}
	>);

	my $pdu_req = $asn_cldap_req->encode(
				msgid => 0,
				basedn => "",
				scope => 0,
				dereference => 0,
				sizelimit => 0,
				timelimit => 0,
				attronly => 0,
				dnsdom_attr => $domain ? 'DnsDomain' : "",
				dnsdom_val => $domain ? $domain : "",
				host_attr => 'Host',
				host_val => $host,
				ntver_attr => 'NtVer',
				ntver_val => $ntver,
				netlogon => 'NetLogon',
				) || die "failed to encode pdu: $@";

	if ($opt_debug) {
		print"------------\n";
		asn_dump($pdu_req);
		print"------------\n";
	}

	return $sock->send($pdu_req) || die "no send: $@";
}

# from source/libads/cldap.c :
#
#/*
#  These seem to be strings as described in RFC1035 4.1.4 and can be:
#
#   - a sequence of labels ending in a zero octet
#   - a pointer
#   - a sequence of labels ending with a pointer
#
#  A label is a byte where the first two bits must be zero and the remaining
#  bits represent the length of the label followed by the label itself.
#  Therefore, the length of a label is at max 64 bytes.  Under RFC1035, a
#  sequence of labels cannot exceed 255 bytes.
#
#  A pointer consists of a 14 bit offset from the beginning of the data.
#
#  struct ptr {
#    unsigned ident:2; // must be 11
#    unsigned offset:14; // from the beginning of data
#  };
#
#  This is used as a method to compress the packet by eliminated duplicate
#  domain components.  Since a UDP packet should probably be < 512 bytes and a
#  DNS name can be up to 255 bytes, this actually makes a lot of sense.
#*/

sub pull_netlogon_string (\$$$) {

	my ($ret, $ptr, $str) = @_;

	my $pos = $ptr;

	my $followed_ptr = 0;
	my $ret_len = 0;

	my $retp = pack("x$MAX_DNS_LABEL");

	do {

		$ptr = unpack("c", substr($str, $pos, 1));
		$pos++;

		if (($ptr & 0xc0) == 0xc0) {

			my $len;

			if (!$followed_ptr) {
				$ret_len += 2;
				$followed_ptr = 1;
			}

			my $tmp0 = $ptr; #unpack("c", substr($str, $pos-1, 1));
			my $tmp1 = unpack("c", substr($str, $pos, 1));

			if ($opt_debug) {
				printf("tmp0: 0x%x\n", $tmp0);
				printf("tmp1: 0x%x\n", $tmp1);
			}

			$len = (($tmp0 & 0x3f) << 8) | $tmp1;
			$ptr = unpack("c", substr($str, $len, 1));
			$pos = $len;

		} elsif ($ptr) {

			my $len = scalar $ptr;

			if ($len + 1 > $MAX_DNS_LABEL) {
				warn("invalid string size: %d", $len + 1);
				return 0;
			}

			$ptr = unpack("a*", substr($str, $pos, $len));

			$retp = sprintf("%s%s\.", $retp, $ptr);

			$pos += $len;
			if (!$followed_ptr) {
				$ret_len += $len + 1;
			}
		}

	} while ($ptr);

	$retp =~ s/\.$//; #ugly hack...

	$$ret = $retp;

	return $followed_ptr ? $ret_len : $ret_len + 1;
}

sub dump_cldap_flags ($) {

	my $flags = shift || return;
	printf("Flags:\n".
		 "\tIs a PDC:                                   %s\n".
		 "\tIs a GC of the forest:                      %s\n".
		 "\tIs an LDAP server:                          %s\n".
		 "\tSupports DS:                                %s\n".
		 "\tIs running a KDC:                           %s\n".
		 "\tIs running time services:                   %s\n".
		 "\tIs the closest DC:                          %s\n".
		 "\tIs writable:                                %s\n".
		 "\tHas a hardware clock:                       %s\n".
		 "\tIs a non-domain NC serviced by LDAP server: %s\n",
		 ($flags & $cldap_flags{ADS_PDC}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_GC}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_LDAP}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_DS}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_KDC}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_TIMESERV}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_CLOSEST}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_WRITABLE}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_GOOD_TIMESERV}) ? "yes" : "no",
		 ($flags & $cldap_flags{ADS_NDNC}) ? "yes" : "no");
}

sub guid_to_string ($) {

	my $guid = shift || return undef;
	if ((my $len = length $guid) != 16) {
		printf("invalid length: %d\n", $len);
		return undef;
	}
	my $string = sprintf "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		unpack("I", $guid),
		unpack("S", substr($guid, 4, 2)),
		unpack("S", substr($guid, 6, 2)),
		unpack("C", substr($guid, 8, 1)),
		unpack("C", substr($guid, 9, 1)),
		unpack("C", substr($guid, 10, 1)),
		unpack("C", substr($guid, 11, 1)),
		unpack("C", substr($guid, 12, 1)),
		unpack("C", substr($guid, 13, 1)),
		unpack("C", substr($guid, 14, 1)),
		unpack("C", substr($guid, 15, 1));
	return lc($string);
}

sub recv_cldap_netlogon ($\$) {

	my ($sock, $return_string) = @_;
	my ($ret, $pdu_out);

	$ret = $sock->recv($pdu_out, 8192) || die "failed to read from socket: $@";
	#$ret = sysread($sock, $pdu_out, 8192);

	if ($opt_debug) {
		print"------------\n";
		asn_dump($pdu_out);
		print"------------\n";
	}

	my $asn_cldap_rep = Convert::ASN1->new;
	my $asn_cldap_rep_fail = Convert::ASN1->new;

	$asn_cldap_rep->prepare(q<
		SEQUENCE {
			msgid INTEGER,
			[APPLICATION 4] SEQUENCE {
				dn OCTET STRING,
				SEQUENCE {
					SEQUENCE {
						attr OCTET STRING,
						SET {
							val OCTET STRING
						}
					}
				}
			}
		}
		SEQUENCE {
			msgid2 INTEGER,
			[APPLICATION 5] SEQUENCE {
				error_code ENUMERATED,
				matched_dn OCTET STRING,
				error_message OCTET STRING
			}
		}
	>);

	$asn_cldap_rep_fail->prepare(q<
		SEQUENCE {
			msgid2 INTEGER,
			[APPLICATION 5] SEQUENCE {
				error_code ENUMERATED,
				matched_dn OCTET STRING,
				error_message OCTET STRING
			}
		}
	>);

	my $asn1_rep =  $asn_cldap_rep->decode($pdu_out) ||
			$asn_cldap_rep_fail->decode($pdu_out) ||
			die "failed to decode pdu: $@";

	if ($asn1_rep->{'error_code'} == 0) {
		$$return_string = $asn1_rep->{'val'};
	}

	return $ret;
}

sub parse_cldap_reply ($) {

	my $str = shift || return undef;
        my %hash;
	my $p = 0;

	$hash{type} 	= unpack("L", substr($str, $p, 4)); $p += 4;
	$hash{flags} 	= unpack("L", substr($str, $p, 4)); $p += 4;
	$hash{guid} 	= unpack("a16", substr($str, $p, 16)); $p += 16;

	$p += pull_netlogon_string($hash{forest}, $p, $str);
	$p += pull_netlogon_string($hash{domain}, $p, $str);
	$p += pull_netlogon_string($hash{hostname}, $p, $str);
	$p += pull_netlogon_string($hash{netbios_domain}, $p, $str);
	$p += pull_netlogon_string($hash{netbios_hostname}, $p, $str);
	$p += pull_netlogon_string($hash{unk}, $p, $str);

	if ($hash{type} == $cldap_samlogon_types{SAMLOGON_AD_R}) {
		$p += pull_netlogon_string($hash{user_name}, $p, $str);
	} else {
		$hash{user_name} = "";
	}

	$p += pull_netlogon_string($hash{server_site_name}, $p, $str);
	$p += pull_netlogon_string($hash{client_site_name}, $p, $str);

	$hash{version} 		= unpack("L", substr($str, $p, 4)); $p += 4;
	$hash{lmnt_token} 	= unpack("S", substr($str, $p, 2)); $p += 2;
	$hash{lm20_token} 	= unpack("S", substr($str, $p, 2)); $p += 2;

	return %hash;
}

sub display_cldap_reply {

	my $server = shift;
        my (%hash) = @_;

	my ($name,$aliases,$addrtype,$length,@addrs) = gethostbyname($server);

	printf("Information for Domain Controller: %s\n\n", $name);

	printf("Response Type: ");
	if ($hash{type} == $cldap_samlogon_types{SAMLOGON_AD_R}) {
		printf("SAMLOGON_USER\n");
	} elsif ($hash{type} == $cldap_samlogon_types{SAMLOGON_AD_UNK_R}) {
		printf("SAMLOGON\n");
	} else {
		printf("unknown type 0x%x, please report\n", $hash{type});
	}

	# guid
	printf("GUID: %s\n", guid_to_string($hash{guid}));

	# flags
	dump_cldap_flags($hash{flags});

	# strings
	printf("Forest:\t\t\t%s\n", $hash{forest});
	printf("Domain:\t\t\t%s\n", $hash{domain});
	printf("Domain Controller:\t%s\n", $hash{hostname});

	printf("Pre-Win2k Domain:\t%s\n", $hash{netbios_domain});
	printf("Pre-Win2k Hostname:\t%s\n", $hash{netbios_hostname});

	if ($hash{unk}) {
		printf("Unk:\t\t\t%s\n", $hash{unk});
	}
	if ($hash{user_name}) {
		printf("User name:\t%s\n", $hash{user_name});
	}

	printf("Server Site Name:\t%s\n", $hash{server_site_name});
	printf("Client Site Name:\t%s\n", $hash{client_site_name});

	# some more int
	printf("NT Version:\t\t%d\n", $hash{version});
	printf("LMNT Token:\t\t%.2x\n", $hash{lmnt_token});
	printf("LM20 Token:\t\t%.2x\n", $hash{lm20_token});
}

sub main() {

	my ($ret, $sock, $reply);

	GetOptions(
		'debug'		=> \$opt_debug,
		'domain|d=s'	=> \$opt_domain,
		'help'		=> \$opt_help,
		'host|h=s'	=> \$opt_host,
		'server|s=s'	=> \$opt_server,
	);

	$server = $server || $opt_server;
	$domain = $domain || $opt_domain || undef;
	$host = $host || $opt_host;
	if (!$host) {
		$host = `/bin/hostname`;
		chomp($host);
	}

	if (!$server || !$host || $opt_help) {
		usage();
		exit 1;
	}

	my $ntver = sprintf("%c%c%c%c", 6,0,0,0);

	$sock = connect_cldap($server);
	if (!$sock) {
		die("could not connect to $server");
	}

	$ret = send_cldap_netlogon($sock, $domain, $host, $ntver);
	if (!$ret) {
		close($sock);
		die("failed to send CLDAP request to $server");
	}

	$ret = recv_cldap_netlogon($sock, $reply);
	if (!$ret) {
		close($sock);
		die("failed to receive CLDAP reply from $server");
	}
	close($sock);

	if (!$reply) {
		printf("no 'NetLogon' attribute received\n");
		exit 0;
	}

	%cldap_netlogon_reply = parse_cldap_reply($reply);
	if (!%cldap_netlogon_reply) {
		die("failed to parse CLDAP reply from $server");
	}

	display_cldap_reply($server, %cldap_netlogon_reply);

	exit 0;
}

main();
EOF

# security-checks.sh ------------------------------------------------
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
        state "User exists" 0
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
    elif [ $SRCH_RESULT -eq 49 ]; then
        state "Invalid credentials - ldap_bind(49)" 1
    elif [ $SRCH_RESULT -eq 10 ]; then
        state "Possible invalid BaseDN - ldap_bind(10)" 1
    elif [ $SRCH_RESULT -eq 255 ]; then
        state "Not able to find the LDAP server specified" 1
    elif [ $SRCH_RESULT -eq 34 ]; then
        state "Invalid DN syntax (34)" 1
    else
        state -e "Unrecognized error occured. Not able to connect to AD using\n\tLDAPURI: ${ARG_LDAPURI}\n\tBINDDN: ${ARG_BINDDN}\n\tSEARCHBASE: ${ARG_SEARCHBASE}\n\tand provided password" 1
    fi
}

# checks.sh ------------------------------------------------
#!/usr/bin/env bash

function check_java() {
    # The following candidate list is from CM agent:
    # Starship/cmf/agents/cmf/service/common/cloudera-config.sh
    local JAVA6_HOME_CANDIDATES=(
        '/usr/lib/j2sdk1.6-sun'
        '/usr/lib/jvm/java-6-sun'
        '/usr/lib/jvm/java-1.6.0-sun-1.6.0'
        '/usr/lib/jvm/j2sdk1.6-oracle'
        '/usr/lib/jvm/j2sdk1.6-oracle/jre'
        '/usr/java/jdk1.6'
        '/usr/java/jre1.6'
    )
    local OPENJAVA6_HOME_CANDIDATES=(
        '/usr/lib/jvm/java-1.6.0-openjdk'
        '/usr/lib/jvm/jre-1.6.0-openjdk'
    )
    local JAVA7_HOME_CANDIDATES=(
        '/usr/java/jdk1.7'
        '/usr/java/jre1.7'
        '/usr/lib/jvm/j2sdk1.7-oracle'
        '/usr/lib/jvm/j2sdk1.7-oracle/jre'
        '/usr/lib/jvm/java-7-oracle'
    )
    local OPENJAVA7_HOME_CANDIDATES=(
        '/usr/lib/jvm/java-1.7.0-openjdk'
        '/usr/lib/jvm/java-7-openjdk'
    )
    local JAVA8_HOME_CANDIDATES=(
        '/usr/java/jdk1.8'
        '/usr/java/jre1.8'
        '/usr/lib/jvm/j2sdk1.8-oracle'
        '/usr/lib/jvm/j2sdk1.8-oracle/jre'
        '/usr/lib/jvm/java-8-oracle'
    )
    local OPENJAVA8_HOME_CANDIDATES=(
        '/usr/lib/jvm/java-1.8.0-openjdk'
        '/usr/lib/jvm/java-8-openjdk'
    )
    local MISCJAVA_HOME_CANDIDATES=(
        '/Library/Java/Home'
        '/usr/java/default'
        '/usr/lib/jvm/default-java'
        '/usr/lib/jvm/java-openjdk'
        '/usr/lib/jvm/jre-openjdk'
    )
    local JAVA_HOME_CANDIDATES=(
        ${JAVA7_HOME_CANDIDATES[@]}
        ${JAVA8_HOME_CANDIDATES[@]}
        ${JAVA6_HOME_CANDIDATES[@]}
        ${MISCJAVA_HOME_CANDIDATES[@]}
        ${OPENJAVA7_HOME_CANDIDATES[@]}
        ${OPENJAVA8_HOME_CANDIDATES[@]}
        ${OPENJAVA6_HOME_CANDIDATES[@]}
    )

    # Find and verify Java
    # https://www.cloudera.com/documentation/enterprise/release-notes/topics/rn_consolidated_pcm.html#pcm_jdk
    # JDK 7 minimum required version is JDK 1.7u55
    # JDK 8 minimum required version is JDK 1.8u31
    #   excluldes JDK 1.8u40, JDK 1.8u45, and JDK 1.8u60
    for candidate_regex in "${JAVA_HOME_CANDIDATES[@]}"; do
        # shellcheck disable=SC2045,SC2086
        for candidate in $(ls -rvd ${candidate_regex}* 2>/dev/null); do
            if [ -x "$candidate/bin/java" ]; then
                VERSION_STRING=$("$candidate"/bin/java -version 2>&1)
                RE_JAVA_GOOD='java[[:space:]]version[[:space:]]\"1\.([0-9])\.0_([0-9][0-9]*)\"'
                RE_JAVA_BAD='openjdk[[:space:]]version[[:space:]]\"1\.[0-9]\.'
                if [[ $VERSION_STRING =~ $RE_JAVA_GOOD ]]; then
                    if [[ ${BASH_REMATCH[1]} -eq 7 ]]; then
                        if [[ ${BASH_REMATCH[2]} -lt 55 ]]; then
                            state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                        else
                            state "Java: Supported Oracle Java: ${candidate}/bin/java" 0
                        fi
                    elif [[ ${BASH_REMATCH[1]} -eq 8 ]]; then
                        if [[ ${BASH_REMATCH[2]} -lt 31 ]]; then
                            state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                        elif [[ ${BASH_REMATCH[2]} -eq 40 ]]; then
                            state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                        elif [[ ${BASH_REMATCH[2]} -eq 45 ]]; then
                            state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                        elif [[ ${BASH_REMATCH[2]} -eq 60 ]]; then
                            state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 1
                        elif [[ ${BASH_REMATCH[2]} -eq 75 ]]; then
                            state "Java: Oozie will not work on this Java (OOZIE-2533): ${candidate}/bin/java" 2
                        else
                            state "Java: Supported Oracle Java: ${candidate}/bin/java" 0
                        fi
                    else
                        state "Java: Unsupported Oracle Java: ${candidate}/bin/java" 0
                    fi
                elif [[ $VERSION_STRING =~ $RE_JAVA_BAD ]]; then
                    state "Java: Unsupported OpenJDK: ${candidate}/bin/java" 1
                else
                    state "Java: Unsupported Unknown: ${candidate}/bin/java" 1
                fi
            fi
        done
    done
}

function check_os() (
    function check_swappiness() {
        # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__section_xpq_sdf_jq
        local swappiness
        local msg="System: /proc/sys/vm/swappiness should be 1"
        swappiness=$(cat /proc/sys/vm/swappiness)
        if [ "$swappiness" -eq 1 ]; then
            state "$msg" 0
        else
            state "$msg. Actual: $swappiness" 1
        fi
    }

    function check_tuned() {
        # "tuned" service should be disabled on RHEL/CentOS 7.x
        # https://www.cloudera.com/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__disable-tuned
        if is_centos_rhel_7; then
            systemctl status tuned &>/dev/null
            case $? in
                0) state "System: tuned is running" 1;;
                3) state "System: tuned is not running" 0;;
                *) state "System: tuned is not installed" 0;;
            esac
            if [ "$(systemctl is-enabled tuned 2>/dev/null)" == "enabled" ]; then
                state "System: tuned auto-starts on boot" 1
            else
                state "System: tuned does not auto-start on boot" 0
            fi
        fi
    }

    function check_thp() {
        # Older RHEL/CentOS versions use [1], while newer versions (e.g. 7.1) and
        # Ubuntu/Debian use [2]:
        #   1: /sys/kernel/mm/redhat_transparent_hugepage/defrag
        #   2: /sys/kernel/mm/transparent_hugepage/defrag.
        # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/cdh_admin_performance.html#xd_583c10bfdbd326ba-7dae4aa6-147c30d0933--7fd5__section_hw3_sdf_jq
        local file
        file=$(find /sys/kernel/mm/ -type d -name '*transparent_hugepage')/defrag
        if [ -f "$file" ]; then
            local msg="System: $file should be disabled"
            if grep -F -q "[never]" "$file"; then
                state "$msg" 0
            else
                state "$msg. Actual: $(awk '{print $1}' "$file" | sed -e 's/\[//' -e 's/\]//')" 1
            fi
        else
            state "System: /sys/kernel/mm/*transparent_hugepage not found. Check skipped" 2
        fi
    }

    function check_selinux() {
        # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/install_cdh_disable_selinux.html
        local msg="System: SELinux should be disabled"
        case $(getenforce) in
            Disabled|Permissive) state "$msg" 0;;
            *)                   state "$msg. Actual: $(getenforce)" 1;;
        esac
    }

    # Check that the system clock is synced by either ntpd or chronyd. Chronyd
    # is on CentOS/RHEL 7 and above only.
    # https://community.cloudera.com/t5/Cloudera-Manager-Installation/Should-Cloudera-NTP-use-Chrony-or-NTPD/td-p/55986
    function check_time_sync() (
        function is_ntp_in_sync() {
            if [ "$(ntpstat | grep -c "synchronised to NTP server")" -eq 1 ]; then
                state "System: ntpd clock synced" 0
            else
                state "System: ntpd clock NOT synced. Check 'ntpstat'" 1
            fi
        }

        if is_centos_rhel_7; then
            get_service_state 'ntpd'
            if [ "${SERVICE_STATE['running']}" = true ]; then
                # If ntpd is running, then chrony shouldn't be
                _check_service_is_running 'System' 'ntpd'
                is_ntp_in_sync
                _check_service_is_not_running 'System' 'chronyd'
            else
                _check_service_is_running 'System' 'chronyd'
            fi
        else
            _check_service_is_running 'System' 'ntpd'
        fi
    )

    function check_32bit_packages() {
        local packages_32bit
        packages_32bit=$(rpm -qa --queryformat '\t%{NAME} %{ARCH}\n' | grep 'i[6543]86' | cut -d' ' -f1)
        if [ "$packages_32bit" ]; then
            state "System: Found the following 32bit packages installed:\n$packages_32bit" 1
        else
            state "System: Only 64bit packages should be installed" 0
        fi
    }

    function check_unneeded_services() {
        local UNNECESSARY_SERVICES=(
            'bluetooth'
            'cups'
            'ip6tables'
            'postfix'
        )
        for service_name in "${UNNECESSARY_SERVICES[@]}"; do
            _check_service_is_not_running 'System' "$service_name" 2
        done
    }

    function check_tmp_noexec() {
        local noexec=false
        for option in $(findmnt -lno options --target /tmp | tr ',' ' '); do
            if [[ "$option" = 'noexec' ]]; then
                noexec=true
            fi
        done
        if $noexec; then
            state "System: /tmp mounted with noexec fails for CM versions older than 5.8.4, 5.9.2, and 5.10.0" 2
        else
            state "System: /tmp mounted with noexec fails for CM versions older than 5.8.4, 5.9.2, and 5.10.0" 0
        fi
    }
    function check_entropy() {
        local entropy
        entropy=$(cat /proc/sys/kernel/random/entropy_avail)
        if [ "$entropy" -gt 500 ]; then
            state "System: Entropy is $entropy" 0
        else
            state "System: Entropy should be more than 500, Actual: $entropy -- Please see https://bit.ly/2IoOj0K" 2
        fi
    }
    check_swappiness
    check_tuned
    check_thp
    check_selinux
    check_time_sync
    check_32bit_packages
    check_unneeded_services
    check_tmp_noexec
    check_entropy
)

function check_database() {
    local VERSION_PATTERN='([0-9][0-9]*\.[0-9][0-9]*)\.[0-9][0-9]*'
    local mysql_ver=''
    local mysql_rpm=''
    local mysql_ent
    local mysql_com

    mysql_ent=$(rpm -q --queryformat='%{VERSION}' mysql-commercial-server)
    # shellcheck disable=SC2181
    if [[ $? -eq 0 ]]; then
        mysql_rpm=$(rpm -q mysql-commercial-server)
        [[ $mysql_ent =~ $VERSION_PATTERN ]]
        mysql_ver=${BASH_REMATCH[1]}
    fi

    mysql_com=$(rpm -q --queryformat='%{VERSION}' mysql-community-server)
    # shellcheck disable=SC2181
    if [[ $? -eq 0 ]]; then
        mysql_rpm=$(rpm -q mysql-community-server)
        [[ $mysql_com =~ $VERSION_PATTERN ]]
        mysql_ver=${BASH_REMATCH[1]}
    fi
    if [[ -z "$mysql_ver" ]]; then
        state "Database: MySQL server not installed, skipping version check" 2
        return
    fi

    case "$mysql_ver" in
        '5.1'|'5.5'|'5.6'|'5.7')
            state "Database: Supported MySQL server installed. $mysql_rpm" 0
            ;;
        *)
            state "Database: Unsupported MySQL server installed. $mysql_rpm" 1
            ;;
    esac
}

function check_jdbc_connector() {
    # See Installing the MySQL JDBC Driver
    # https://www.cloudera.com/documentation/enterprise/latest/topics/cm_ig_mysql.html#cmig_topic_5_5_3
    local connector=/usr/share/java/mysql-connector-java.jar
    if [ -f $connector ]; then
        state "Database: MySQL JDBC Driver is installed" 0
    else
        state "Database: MySQL JDBC Driver is not installed" 2
    fi
}

function check_network() (

    function check_hostname() {
        local fqdn
        local short
        fqdn=$(hostname -f)
        short=$(hostname -s)

        # https://en.wikipedia.org/wiki/Hostname
        # Hostnames are composed of series of labels concatenated with dots, as are
        # all domain names. Each label must be from 1 to 63 characters long, and the
        # entire hostname (including delimiting dots but not a trailing dot) has a
        # maximum of 253 ASCII characters.
        local VALID_FQDN='^([a-z]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9\-]{0,61}[a-z0-9])?$'
        echo "$fqdn" | grep -Eiq "$VALID_FQDN"
        local valid_format=$?
        if [[ $valid_format -eq 0 && ${#fqdn} -le 253 ]]; then
            if [[ ${#short} -gt 15 ]]; then
                # Microsoft still recommends computer names less than or equal to 15 characters.
                # https://serverfault.com/questions/123343/is-the-netbios-limt-of-15-charactors-still-a-factor-when-naming-computers
                # https://technet.microsoft.com/en-us/library/cc731383.aspx
                # If hostname is longer than that, we cannot do SSSD or Centrify etc to
                # add the node to domain. Won't work well with Kerberos/AD.
                state "Network: Computer name should be <= 15 characters (NetBIOS restriction)" 1
            else
                if [[ "${fqdn//\.*/}" = "$short" ]]; then
                    if [[ $(echo "$fqdn" | grep '[A-Z]') = "" ]]; then
                        state "Network: Hostname looks good (FQDN, no uppercase letters)" 0
                    else
                        # Cluster hosts must have a working network name resolution system and
                        # correctly formatted /etc/hosts file. All cluster hosts must have properly
                        # configured forward and reverse host resolution through DNS.
                        # The /etc/hosts files must:
                        # - Not contain uppercase hostnames
                        # https://www.cloudera.com/documentation/enterprise/release-notes/topics/rn_consolidated_pcm.html#cm_cdh_compatibility
                        state "Network: Hostname should not contain uppercase letters" 1
                    fi
                else
                    state "Network: Hostname misconfiguration (shortname and host label of FQDN don't match)" 2
                fi
            fi
        else
            # Important
            # - The canonical name of each host in /etc/hosts `must' be the FQDN
            # - Do not use aliases, either in /etc/hosts or in configuring DNS
            # https://www.cloudera.com/documentation/enterprise/latest/topics/cdh_ig_networknames_configure.html
            state "Network: Malformed hostname is configured (consult RFC)" 1
        fi
    }

    # Networking Protocols Support
    # CDH requires IPv4. IPv6 is not supported and must be disabled.
    # https://www.cloudera.com/documentation/enterprise/release-notes/topics/rn_consolidated_pcm.html
    function check_ipv6() {
        local msg="Network: IPv6 is not supported and must be disabled"
        if ip addr show | grep -q inet6; then
            state "${msg}" 1
        else
            state "${msg}" 0
        fi
    }

    function check_etc_hosts() {
        local entries
        entries=$(grep -cEv "^#|^ *$" /etc/hosts)
        local msg="Network: /etc/hosts entries should be <= 2 (use DNS). Actual: $entries"
        if [ "$entries" -le 2 ]; then
            local rc=0
            while read -r line; do
                entry=$(echo "$line" | grep -Ev "^#|^ *$")
                if [ ! "$entry" = "" ]; then
                    # the following line ('set -- $(...)') can't be quoted
                    # shellcheck disable=SC2046
                    set -- $(echo "$line" | awk '{ print $1, $2 }')
                    if [ "$1" = "127.0.0.1" ] || [ "$1" = "::1" ] && [ "$2" = "localhost" ]; then
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
    }

    function check_nscd_and_sssd() {
        _check_service_is_running 'Network' 'nscd'
        local nscd_running=${SERVICE_STATE['running']}
        _check_service_is_running 'Network' 'sssd' 2
        local sssd_running=${SERVICE_STATE['running']}

        if $nscd_running && $sssd_running; then
            # 7.8. USING NSCD WITH SSSD
            # SSSD is not designed to be used with the NSCD daemon.
            # Even though SSSD does not directly conflict with NSCD, using both services
            # can result in unexpected behavior, especially with how long entries are cached.
            # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/System-Level_Authentication_Guide/usingnscd-sssd.html

            # How-to: Deploy Apache Hadoop Clusters Like a Boss
            # Name Service Caching
            # If you’re running Red Hat SSSD, you’ll need to modify the nscd configuration;
            # with SSSD enabled, don’t use nscd to cache passwd, group, or netgroup information.
            # http://blog.cloudera.com/blog/2015/01/how-to-deploy-apache-hadoop-clusters-like-a-boss/
            # shellcheck disable=SC2013
            for cached in $(awk '/^[^#]*enable-cache.*yes/ { print $2 }' /etc/nscd.conf); do
                case $cached in
                    'passwd'|'group'|'netgroup')
                        state "Network: nscd should not cache $cached with sssd enabled" 1
                        ;;
                    *)
                        ;;
                esac
            done
            # shellcheck disable=SC2013
            for non_cached in $(awk '/^[^#]*enable-cache.*no/ { print $2 }' /etc/nscd.conf); do
                case $non_cached in
                    'passwd'|'group'|'netgroup')
                        state "Network: nscd shoud not cache $non_cached with sssd enabled" 0
                        ;;
                    *)
                        ;;
                esac
            done
        fi
    }

    # Consistency check on forward (hostname to ip address) and
    # reverse (ip address to hostname) resolutions.
    # Note that an additional `.' in the PTR ANSWER SECTION.
    function check_dns() {
        which dig 2&>/dev/null
        if [ $? -eq 2 ]; then
            state "Network: 'dig' not found, skipping DNS checks. Run 'sudo yum install bind-utils' to fix." 2
            return
        fi

        local fqdn
        local fwd_lookup
        local rvs_lookup
        fqdn=$(hostname -f)
        fwd_lookup=$(dig -4 "$fqdn" A +short)
        rvs_lookup=$(dig -4 -x "$fwd_lookup" PTR +short)
        if [[ "${fqdn}." = "$rvs_lookup" ]]; then
            state "Network: Consistent name resolution of $fqdn" 0
        else
            state "Network: Inconsistent name resolution of $fqdn. Check DNS configuration" 1
        fi
    }
    check_ipv6
    check_hostname
    check_etc_hosts
    check_nscd_and_sssd
    check_dns
)

function check_firewall() {
    # http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/install_cdh_disable_iptables.html
    if is_centos_rhel_7; then
        _check_service_is_not_running 'Network' 'firewalld'
    else
        _check_service_is_not_running 'Network' 'iptables'
    fi
}

function checks() (
    print_header "Prerequisite checks"
    reset_service_state
    check_os
    check_network
    check_firewall
    check_java
    check_database
    check_jdbc_connector
)

# info.sh ------------------------------------------------
#!/usr/bin/env bash

function print_time() {
    local timezone
    timezone=$(date | awk '{print $(NF-1)}')
    timezone=${timezone:-UTC}
    print_label "Timezone" "$timezone"
    print_label "DateTime" "$(date)"
}

function print_fqdn() {
    print_label "FQDN" "$(hostname -f)"
}

function print_os() {
    local distro="Unknown"
    if [ -f /etc/redhat-release ]; then
        distro=$( sed -e 's/ release / /' \
            -e 's/ ([[:alnum:]]*)//' \
            -e 's/CentOS Linux \([0-9]\).\([0-9]\).*/CentOS \1.\2/' \
            /etc/redhat-release )
    fi
    print_label "Distro" "$distro"
    print_label "Kernel" "$(uname -r)"
}

function print_cpu_and_ram() {
    local cpu
    cpu=$(grep -m1 "^model name" /proc/cpuinfo | cut -d' ' -f3- | sed -e 's/(R)//' -e 's/Core(TM) //' -e 's/CPU //')
    print_label "CPUs" "$(nproc)x $cpu"
    # Total installed memory (MemTotal and SwapTotal in /proc/meminfo)
    print_label "RAM" "$(awk '/^MemTotal:/ { printf "%.2f", $2/1024/1024 ; exit}' /proc/meminfo)G"
}

function print_disks() (
    function data_mounts() {
        while read -r source target fstype options; do
            local NOATIME=false
            for option in $(echo "$options" | tr ',' ' '); do
                if [[ $option = 'noatime' ]]; then
                    NOATIME=true
                fi
            done
            echo -n "$source $target "
            case $fstype in
                'xfs')
                    local resblks
                    resblks=$(xfs_io -xc resblks "$target" | awk '/^reserved blocks =/ { print $4 }')
                    echo -en "\e[92m$fstype\033[0m, "
                    if [[ $resblks -eq 0 ]]; then
                        echo -en "\e[92mNo\033[0m reserved blocks, "
                    else
                        echo -en "\e[93m$resblks\033[0m blocks reserved, "
                    fi
                    if ${NOATIME}; then
                        echo -e "\e[92mnoatime\033[0m option specified|"
                    else
                        echo -e "without \e[93mnoatime\033[0m option|"
                    fi
                    ;;
                'ext3'|'ext4')
                    local resblks
                    resblks=$(tune2fs -l "$source" | awk '/^Reserved block count:/ { print $4 }')
                    echo -en "\e[92m$fstype\033[0m, "
                    if [[ $resblks -eq 0 ]]; then
                        echo -en "\e[92mNo\033[0m reserved blocks, "
                    else
                        echo -en "\e[93m$resblks\033[0m blocks reserved, "
                    fi
                    if ${NOATIME}; then
                        echo -e "\e[92mnoatime\033[0m option specified|"
                    else
                        echo -e "without \e[93mnoatime\033[0m option|"
                    fi
                    ;;
                *)
                    echo -e "\e[91m$fstype\033[0m is not recommended for a data mount|"
                    ;;
            esac
        done
    }
    echo "Disks:"
    # shellcheck disable=SC2045
    for d in $(ls /dev/{sd?,xvd?} 2>/dev/null); do
        pad; echo -n "$d  "
        sudo fdisk -l "$d" 2>/dev/null | grep "^Disk /dev/" | cut -d' ' -f3-4 | cut -d',' -f1
    done
    echo "Mount:"
    findmnt -lo source,target,fstype,options | grep '^/dev' | \
        while read -r line; do
            pad; echo "$line"
        done
    echo "Data mounts:"
    local DATA_MOUNTS
    DATA_MOUNTS=$( findmnt -lno source,target,fstype,options | \
        grep -E '[[:space:]]/data' | data_mounts )
    if [[ -z ${DATA_MOUNTS} ]]; then
        pad; echo "None found"
    else
        local IFS='|'
        echo "$DATA_MOUNTS" | while read -r line; do
            pad; echo "$line"
        done
    fi
)

function print_free_space() (
    function free_space() {
        # Pick "Avail" column as "Free space:"
        # $ df -Ph /opt
        # Filesystem      Size  Used Avail Use% Mounted on
        # /dev/sda1        99G  1.8G   92G   2% /
        local path="$1"
        local free
        free=$(df -Ph "$path" | tail -1 | awk '{print $4}')
        pad
        printf "%-9s %s\n" "$path" "$free"
    }
    echo "Free space:"
    free_space /opt
    free_space /var/log
)

function print_cloudera_rpms() {
    local rpms
    rpms=$(echo -e "$RPM_QA" | grep "^cloudera-")
    if [ "$rpms" ]; then
        echo "Cloudera RPMs:"
        local pkg
        local ver
        for line in $rpms; do
            pkg=$(echo "$line" | cut -d'-' -f1-3)
            ver=$(echo "$line" | cut -d'-' -f4-)
            pad
            printf "%-24s  %s\n" "$pkg" "$ver"
        done
    else
        echo "Cloudera RPMs: None installed"
    fi
}

function print_network() {
    print_label "nsswitch" "$(grep "^hosts:" /etc/nsswitch.conf | sed 's/^hosts: *//')"
    print_label "DNS server" "$(grep "^nameserver" /etc/resolv.conf | cut -d' ' -f2)"
}

function print_internet() {
  if [ "$(ping -W1 -c1 8.8.8.8 &>/dev/null; echo $?)" -eq 0 ]; then
    print_label "Internet" "Yes"
  else
    print_label "Internet" "No"
  fi
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
    print_internet
}

# utils.sh ------------------------------------------------
#!/usr/bin/env bash

# Global array variable for passing service state. Set by get_service_state().
declare -A SERVICE_STATE

SYSINFO_TITLE_WIDTH=14

function print_label() {
    printf "%-${SYSINFO_TITLE_WIDTH}s %s\n" "$1:" "$2"
}

function print_header() {
    echo
    echo "$*"
    echo "-------------------"
}

function pad() {
    printf "%$((SYSINFO_TITLE_WIDTH+1))s" " "
}

# Print state with coloured OK/FAIL prefix
function state() {
    local msg=$1
    local flag=$2
    if [ "$flag" -eq 0 ]; then
        echo -e "\e[92m PASS \033[0m $msg"
    elif [ "$flag" -eq 2 ]; then
        echo -e "\e[93m WARN \033[0m $msg"
    else
        echo -e "\e[91m FAIL \033[0m $msg"
    fi
}

# Checks that the specified service is installed, running, and auto-started on boot.
function _check_service_is_running() {
    local prefix="$1"
    local service_name="$2"
    local msgflag="${3:-1}"

    [ -z "$prefix" ]       && die "Prefix not specified"
    [ -z "$service_name" ] && die "Service name not specified"

    get_service_state "$service_name"

    if [ "${SERVICE_STATE['installed']}" = true ]; then
        if [ "${SERVICE_STATE['running']}" = true ]; then
            state "$prefix: $service_name is running" 0
        else
            state "$prefix: $service_name is not running" "$msgflag"
        fi

        if [ "${SERVICE_STATE['autostart']}" = true ]; then
            state "$prefix: $service_name auto-starts on boot" 0
        else
            state "$prefix: $service_name does not auto-start on boot" "$msgflag"
        fi
    else
        state "$prefix: $service_name is not installed" "$msgflag"
    fi
}

# Checks that the specified service is NOT installed, running, or auto-started on boot.
function _check_service_is_not_running() {
    local prefix="$1"
    local service_name="$2"
    local msgflag="${3:-1}"

    [ -z "$prefix" ]       && die "Prefix not specified"
    [ -z "$service_name" ] && die "Service name not specified"

    get_service_state "$service_name"

    if [ "${SERVICE_STATE['installed']}" = true ]; then
        if [ "${SERVICE_STATE['running']}" = true ]; then
            state "$prefix: $service_name should not be running" "$msgflag"
        else
            state "$prefix: $service_name is not running" 0
        fi

        if [ "${SERVICE_STATE['autostart']}" = true ]; then
            state "$prefix: $service_name should not auto-start on boot" "$msgflag"
        else
            state "$prefix: $service_name does not auto-start on boot" 0
        fi
    else
        state "$prefix: $service_name is not installed" 0
    fi
}

function is_centos_rhel_7() {
    if [ -f /etc/redhat-release ] && grep -q " 7." /etc/redhat-release; then
        return 0;
    else
        return 1;
    fi
}

function reset_service_state() {
    SERVICE_STATE['installed']=false
    SERVICE_STATE['running']=false
    SERVICE_STATE['autostart']=false
}

function die() {
    echo "ERROR: $*. Aborting!"
    exit 2
}

function get_service_state() {
    local service_name="$1"

    [ -z "$service_name" ] && die "Service name not specified"

    reset_service_state

    if is_centos_rhel_7; then
        local sub_state
        sub_state=$(systemctl show "$service_name" --type=service --property=SubState 2</dev/null | sed -e 's/^.*=//')
        case $sub_state in
            'running')  SERVICE_STATE['installed']=true
                        SERVICE_STATE['running']=true
                        ;;
            'dead')     SERVICE_STATE['installed']=true
                        ;;
        esac

        systemctl is-enabled "$service_name" --type=service --quiet 2</dev/null
        case $? in
            0)  SERVICE_STATE['autostart']=true
                ;;
        esac
    else
        # Most services don't need sudo, but some like iptables do even for status.
        sudo service "$service_name" status 2&>/dev/null
        case $? in
            0)  SERVICE_STATE['installed']=true
                SERVICE_STATE['running']=true
                ;;
            3)  SERVICE_STATE['installed']=true
                ;;
        esac

        local autostart
        autostart=$(chkconfig 2>/dev/null | awk "/^$service_name / {print \$5}")
        if [ "$autostart" = "3:on" ]; then
            SERVICE_STATE['autostart']=true
        fi
    fi

    if [ "$DEBUG" = true ]; then
        echo "$service_name installed: ${SERVICE_STATE['installed']}"
        echo "$service_name running:   ${SERVICE_STATE['running']}"
        echo "$service_name autostart: ${SERVICE_STATE['autostart']}"
    fi
}

# prereq-check-dev.sh (main) ------------------------------------------------

BANNER="Cloudera Manager & CDH Prerequisites Checks v$VER"

function usage() {
    SCRIPTNAME=$(basename "${BASH_SOURCE[0]}")
    echo "$(tput bold)NAME:$(tput sgr0)"
    echo "  ${SCRIPTNAME} - ${BANNER}"
    echo
    echo "$(tput bold)SYNOPSIS:$(tput sgr0)"
    echo "  ${SCRIPTNAME} [options]"
    echo
    echo "$(tput bold)OPTIONS:$(tput sgr0)"
    echo "  -h, --help"
    echo "    Show this message"
    echo
    echo "  -a, --addc $(tput smul)domain$(tput sgr0)"
    echo "    Run tests against Active Directory Domain Controller"
    echo
    echo "  -p, --privilegetest $(tput smul)ldapURI$(tput sgr0) $(tput smul)binddn$(tput sgr0) $(tput smul)searchbase$(tput sgr0) $(tput smul)bind_user_password$(tput sgr0)"
    echo "    Run tests against Active Directory delegated user for Direct to AD integration"
    echo "    http://blog.cloudera.com/blog/2014/07/new-in-cloudera-manager-5-1-direct-active-directory-integration-for-kerberos-authentication/"
    echo
    exit 1
}

export DEBUG=
OPT_USAGE=
OPT_DOMAIN=
OPT_USER=
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
        check_addc "${ARG_DOMAIN}"
    fi
elif [[ ${OPT_USER} ]]; then
    if [[ -z ${ARG_LDAPURI} || -z ${ARG_BINDDN} || -z ${ARG_SEARCHBASE} || -z ${ARG_USERPSWD} ]]; then
        >&2 echo "Options missing"
        usage
    else
        check_privs "${ARG_LDAPURI}" "${ARG_BINDDN}" "${ARG_SEARCHBASE}"
    fi
else
    echo "${BANNER}"

    # Cache `rpm -qa` since it's slow and we call it several times
    export RPM_QA
    RPM_QA=$(rpm -qa | sort)

    system_info
    checks
    echo
fi
