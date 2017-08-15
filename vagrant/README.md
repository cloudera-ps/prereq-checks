# Vagrant Boxes

## Vagrant Box (CentOS 6.7)

Vagrant boxes that provide a standard and simple way to test our script in the various supported Operating Systems (OS):

 - CentOS 6.7
 - CentOS 7.3

### Initial setup

1. Download and install Vagrant: https://www.vagrantup.com/downloads.html.

### Usage

Use the bundled wrapper script (note the 2 dots in `../v` as it is one level
down):

```
~/prereq-checks/vagrant/centos6.7 # ../v
OPTIONS:
  up
      Start VM

  down
      Suspend VM

  clean
      Re-init VM

  -h, --help
      Show this message
```

#### Booting up and connecting to the VM

To boot up or resume the VM (note the 2 dots in `../v`), for example:
```
~/prereq-checks/vagrant/ # cd centos6.7
~/prereq-checks/vagrant/centos6.7 # ../v up
Bringing machine 'default' up with 'vmware_fusion' provider...
==> default: Cloning VMware VM: 'bento/centos-6.7'. This can take some time...
==> default: Checking if box 'bento/centos-6.7' is up to date...
==> default: Verifying vmnet devices are healthy...
==> default: Preparing network adapters...
...
==> default: Running provisioner: shell...
    default: Running: inline script
==> default: Loaded plugins: fastestmirror
==> default: Setting up Install Process
==> default: Determining fastest mirrors
...
Connecting to VM (press CTRL-d to exit)...
[vagrant@centos67 ~]$
```

You are now inside the VM. Press `CTRL-d` to return to the host system. Run
`../v up` again to reconnect.

Not that the first run will take some time as Vagrant will download the base OS
image and then initialize it. Subsequent runs/connections are quick:

```
~/prereq-checks/vagrant/centos6.7 # ../v up
Bringing machine 'default' up with 'vmware_fusion' provider...
==> default: Checking if box 'bento/centos-6.7' is up to date...
==> default: Machine is already running.
Connecting to VM (press CTRL-d to exit)...
Last login: Tue Aug 15 07:24:24 2017 from 192.168.9.1
```

The combined `prereq-check-single.sh` file should be automatically linked in
the home directory:

```
[vagrant@centos67 ~]$ ls -l
total 0
lrwxrwxrwx. 1 root root 31 Aug 15 07:15 prereq-check-single.sh -> /vagrant/prereq-check-single.sh
[vagrant@centos67 ~]$
```

Which one can then execute directly for testing:

```
[vagrant@centos67 ~]$ ./prereq-check-single.sh
Cloudera Manager & CDH Prerequisites Checks v1.3.0

System information
-------------------
FQDN:          centos67.vagrant.dev
Distro:        CentOS 6.7
Kernel:        2.6.32-573.el6.x86_64
CPUs:          1x Intel i7-5557U @ 3.10GHz
RAM:           490M
Disks:
               /dev/sda  42.9 GB
Mount:
               /dev/mapper/VolGroup-lv_root / ext4 rw,relatime,seclabel,barrier=1,data=ordered
               /dev/sda1 /boot ext4 rw,relatime,seclabel,barrier=1,data=ordered
Data mounts:
               None found
Free space:
               /opt      35G
               /var/log  35G
Cloudera RPMs: None installed
Timezone:      -rw-r--r--. 1 root root 118 May 21  2016 /etc/localtime
DateTime:      Tue Aug 15 07:16:32 UTC 2017
nsswitch:      files dns
DNS server:    192.168.9.2
...
```

Changes made to the original "prereq-check-single.sh" file on the host are
immediately reflected in the VM, and vice versa.

#### Suspending the VM

Suspend the VM when no longer needed to save system resources. For example:
```
~/prereq-checks/vagrant/ # cd centos6.7
~/prereq-checks/vagrant/centos6.7 # ../v down
```

#### Re-initializing the VM

Destroy the VM if you want to start over. For example:
```
~/prereq-checks/vagrant/ # cd centos6.7
~/prereq-checks/vagrant/centos6.7 # ../v clean
```
