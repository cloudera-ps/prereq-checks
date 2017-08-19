# CM & CDH Prerequisites Checker

Bash script for displaying relevant system information and performing
prerequisite checks for Cloudera Manager & CDH installation.

**Motivation**: Ensuring that the long list of required and recommended
prerequisites are correctly applied during a [Hadoop Cluster
Deployment](http://www.cloudera.com/content/www/en-us/services-support/professional-services/cluster-certification.html)
(or similar) engagement is manual, time-consuming, and error-prone (not to
mention mind-numbing).

**Non-Goals**: This is not intended to replace or compete with the
[Cloudera Support Interface (CSI)](http://blog.cloudera.com/blog/2014/02/secrets-of-cloudera-support-inside-our-own-enterprise-data-hub/),
which includes a detailed cluster validation report.

For details on the checks performed, refer to the following:
- [Installation requirements for Cloudera Manager & CDH](http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/installation_reqts.html)
- [Optimizing Performance in CDH](http://www.cloudera.com/content/www/en-us/documentation/enterprise/latest/topics/cdh_admin_performance.html)

## Sample output

The following screenshot shows a run on an configured (or misconfigured)
system:
![Sample run - with failures](images/sample-run-fail.png)

And here's the output on the same server after addressing all the issues:
![Sample run - all passes](images/sample-run-pass.png)

# How to run this checker

Currently there are two ways to run this script.
The first method is to obtain the inspection result from a single host targeting
the host that executed the script.
The second method is to obtain the inspection results from multiple hosts
by using [Ansible](https://www.ansible.com/) to automate distribution and
execution of the script file(s) and gathering the inspection results from
the multiple target hosts.

## Prerequisites
1. For using the distributed mode, run
`    yum install ansible`
2. For using the AD domain controller checks, run
`    yum install perl-Convert-ASN1 bind-utils`
3. For using the AD delegated user privilege checks, run
`    yum install openldap-clients`

## Running it locally

Running the script is easy as it is intentionally written in Bash to avoid any
dependencies. This is to avoid dependency hell in restrictive customer
environments. It does not run on Mac OS. Tested on RHEL/CentOS 6.7 and 7.3 - see the
[vagrant/](vagrant/) subfolder for details. Requires root/superuser permissions
to run.

### Option A - Dev version

To run:

    ./prereq-check-dev.sh

This requires the libraries in `lib/`, which includes both Bash and Perl
libraries.

### Option B - Single file version

To build/update the single file version of the script, run:

    ./build.sh

This produces the file `prereq-check.sh`, same as the 'dev' version but with all
the libs concatenated into this single file for easier handling. To run:

    ./prereq-check.sh

## Usage

```
$ ./prereq-check.sh -h
NAME:
  prereq-check.sh - Cloudera Manager & CDH Prerequisites Checks v1.4.1

SYNOPSIS:
  prereq-check.sh [options]

OPTIONS:
  -h, --help
    Show this message

  -a, --addc domain
    Run tests against Active Directory Domain Controller

  -p, --privilegetest ldapURI binddn searchbase bind_user_password
    Run tests against Active Directory delegated user for Direct to AD integration
    http://blog.cloudera.com/blog/2014/07/new-in-cloudera-manager-5-1-direct-active-directory-integration-for-kerberos-authentication/
```

## Running it with Ansible

Prerequisites checker is also implemented as an Ansible role.
Your Ansible installation should be able to find the `prereq-checks`
ansible role included in this project.
The easiest way is to have a simple `ansible.cfg` file like this:

    [defaults]
    hostfile = inventory/hosts
    host_key_checking = False
    roles_path = roles

Ansible needs inventory files properly configured to work.
At least you have to change `hosts` file to list the target hosts
you would like to inspect.

    % cat inventory/hosts
    #
    # See Ansible Documentation > Inventory > Hosts and Groups
    # http://docs.ansible.com/ansible/latest/intro_inventory.html#hosts-and-groups
    #
    rack01-node01.example.com
    rack01-node02.example.com
    rack01-node03.example.com
    rack01-node04.example.com
    rack02-node01.example.com
    rack02-node02.example.com
    rack02-node03.example.com
    rack02-node04.example.com

A sample ansible playbook is provided as `prereq-check.yml`:

    ---
    - hosts: all
      strategy: free
      gather_facts: no
      become: yes
      become_user: root

      vars:
        outputdir: out

      roles:
        - prereq-checks

You can control the output directory for the inspection results by
assigning a desired path to the `outputdir` variable.
The inspection results are stored at the current directory `./` by default.

Running the above play book will generate the output files under the
`./out/` directory:

    % ansible-playbook prereq-check.yml

Each inspection result file has a name of `<hostname>.out` where
&lt;hostname&gt; is substituted by the name in `hosts` inventory file:

    % ls ./out
    rack01-node01.example.com.out	rack02-node01.example.com.out
    rack01-node02.example.com.out	rack02-node02.example.com.out
    rack01-node03.example.com.out	rack02-node03.example.com.out
    rack01-node04.example.com.out	rack02-node04.example.com.out


## Contributions

Please report any bugs or feature requests using the Github Issues here. Better
yet, send pull requests!
