# CM & CDH Prerequisites Checker

This is a test.

Bash script for displaying relevant system information and performing
prerequisite checks for Cloudera Manager & CDH installation.

Motivation: Ensuring that the long list of required and recommended
prerequisites are correctly applied during a [Hadoop Cluster
Deployment](http://www.cloudera.com/content/www/en-us/services-support/professional-services/cluster-certification.html)
(or similar) engagement is manual, time-consuming, and error-prone (not to
mention mind-numbing).

Non-Goals: This is not intended to replace or compete with the
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

## Running it locally

Running the script is easy as it is intentionally written in Bash to avoid any
dependencies. This is to avoid dependency hell in restrictive customer
environments.

Note that it does not run on Mac OS and has only been tested on RHEL/CentOS 6.5
and 7.3 so far. Your Mileage May Vary.

It requires root/superuser permissions for some commands.

First check out the repository and switch into the newly created directory:

    git clone https://github.com/cloudera-ps/prereq-checks.git
    cd prereq-checks

### Option A

Simply execute the script:

    ./prereq-check.sh

It requires the libraries in `lib/`, as breaking down the code into several
files makes them easier to maintain. If you rather copy around a single file
instead, use Option B.

### Option B

To build the single file version of the script, run:

    ./build-single.sh

This produces the file `prereq-check-single.sh`, which is the exact same code
just with all the libs concatenated into a single file so it's easier to handle.
Simply execute it like in Option A:

    ./prereq-check-single.sh

## Invocations

| Command | |
| --- | --- |
| ./prereq-check.sh | run system check (default) |
| ./prereq-check.sh --help | show usage |
| ./prereq-chesk.sh --security &lt;domain&gt; | run security check |
&lt;domain&gt; : LDAP domain name like AD.CLOUDERA.COM

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
