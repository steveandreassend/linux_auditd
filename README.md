# linux_auditd

Description
===========
This repo provides as a reference the best practice configuration for Linux auditd logging by harmonizing the CIS and STIG standards for RedHat and Oracle Linux.

The CIS (Center for Internet Security) produces various cyber security related services. In particular, it produces benchmarks, which are “configuration guidelines for various technology groups to safeguard systems against today evolving cyber threat" in the words of the CIS.

Security Technical Implementation Guides are published as a tool to improve the security of Department of Defense (DOD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents.

It includes the auditd best practices for tracking LOTL techniques used by threat actors on the Linux OS as advised by the combined advisory of:
* Australian Signals Directorate’s Australian Cyber Security Centre (ASD’s ACSC) in cooperation with the following international partners:
* United States (US) Cybersecurity and Infrastructure Security Agency (CISA), the Federal Bureau of Investigation (FBI) and the National Security Agency (NSA)
* United Kingdom (UK) National Cyber Security Centre (NCSC-UK)
* Canadian Centre for Cyber Security (CCCS)
* New Zealand National Cyber Security Centre (NCSC-NZ) and Computer Emergency Response Team (CERT NZ)
* Japan National Center of Incident Readiness and Strategy for Cybersecurity (NISC) and Computer Emergency Response Team Coordination Center (JPCERT/CC)
* The Republic of Korea National Intelligence Services (NIS) and NIS’s National Cyber Security Center (NCSC-Korea)
* Singapore Cyber Security Agency (CSA)
* The Netherlands General Intelligence and Security Service (AIVD) and Military Intelligence and Security Service (MIVD).


References
==========
* [Center for Internet Security (CIS) compliance in Red Hat Enterprise Linux using OpenSCAP](https://www.redhat.com/en/blog/center-internet-security-cis-compliance-red-hat-enterprise-linux-using-openscap)
* [Red Hat Enterprise Linux 8 (3.0.0)](https://www.cisecurity.org/benchmark/red_hat_linux)
* [Red Hat Enterprise Linux 8 Security Technical Implementation Guide](https://www.stigviewer.com/stig/red_hat_enterprise_linux_8/2023-09-11/MAC-1_Classified/)
* [Best practices for event logging and threat detection](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/best-practices-event-logging-threat-detection?utm_source=linkedin&utm_campaign=event-logging-2024&utm_medium=social&utm_content=publication-2)
* [Identifying and Mitigating Living Off the Land Techniques](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/identifying-and-mitigating-living-off-the-land-techniques)

List of Rules:
===========================

The `/etc/audit/rules.d` directory contains separate files that define individual audit rules.

The files in this directory are organized into groups with following meanings:
```
10 - Kernel and auditctl configuration
20 - Rules that could match general rules but you want a different match
30 - Main rules
40 - Optional rules
50 - Server-specific rules
70 - System local rules
90 - Finalize (immutable)
```
	
The following rules files exist in this repo:
```
10-base-config.rules - initial setup
30-actions.rules - monitor sudo activity
31-audit_rules_usergroup_modification.rules - monitor access to user and group configuration files
32-activity.rules - log commands with elevated privileges or emulating another user
33-access.rules - monitor unsuccessful file modification attempts
34-delete.rules - log all deletion operations performed by users with auid (audit user ID) >= 1000, 
35-logins.rules - tracking user logins attempts, logouts, and current logins
36-session.rules - log any attempts to alter or access critical session files
42-activity.rules - OPTIONAL rules to track all user activity
50-server-specific.rules.example - OPTIONAL rules to track access to installed applications
70-system_local.rules - monitor home dirs, local cron job configs, local firewall configs, sensitive files, local scripts.
71-MAC_policy.rules - tracking attempts to modify Mandatory Access Controls
72-maintenance.rules - monitor all privileged maintenance activities
73-modules.rules - monitor the loading and unloading of kernel modules
73-mounts.rules - audit mount operations on the system
74-perm_mod.rules - monitor changes to file permissions, ownership, and extended attributes
75-privileged.rules - monitor the use of privileged commands and activities performed by users with elevated privileges
76-setgid.rules - monitor and log changes to the set group ID (setgid) permissions on files and directories
77-setuid.rules - monitor and log changes to the set user ID (setuid) permissions on files and directories
78-time_change.rules - tracking attempts to change the sytem time
99-finalize.rules - making the configuration immutable
```

Make sure the config and rules files have the correct permisions:
```bash
# chmod 0640 /etc/audit/rules.d/*.rules
# chmod 0640 /etc/audit/auditd.conf
```

To view logs that match these records, use the key which is specified within the corresponding *.rules file:
```bash
# ausearch -k logins
```

To generate the rules file:
===========================

The Linux Audit daemon auditd can be configured to use the augenrules program to read audit rules files (*. rules) located
in /etc/audit/rules.d location and compile them to create the resulting form of the /etc/audit/audit.rules configuration
file during the daemon startup (default configuration). Alternatively, the auditd daemon can use the auditctl utility to read
audit rules from the /etc/audit/audit.rules configuration file during daemon startup, and load them into the kernel. The
expected behavior is configured via the appropriate ExecStartPost directive setting in the /usr/lib/systemd/system/auditd.service
configuration file.

To instruct the auditd daemon to use the augenrules program to read audit rules (default configuration), use the following setting
in the /usr/lib/systemd/system/auditd.service configuration file:
```
ExecStartPost=-/sbin/augenrules --load
```

To instruct the auditd daemon to use the auditctl utility to read audit rules, use the following setting
in the /usr/lib/systemd/system/auditd.service configuration file:
```
ExecStartPost=-/sbin/auditctl -R /etc/audit/audit.rules
```

The augenrules script reads rules located in the /etc/audit/rules.d/ directory and compiles them into an audit.rules file. This
script processes all files that end with .rules in a specific order based on their natural sort order.

```bash
# augenrules --load
# cat /etc/audit/audit.rules
```

Activate Rules
======================

Restarting auditd with systemctl is prevented if there are dependendies:
```bash
# systemctl status auditd.service
# systemctl list-dependencies auditd.service
```

Restarting the OS will activate the new auditing configuration:
```bash
# reboot
# systemctl status auditd
```

List the configured rules:
```bash
# sudo auditctl -l
```

To re-load the rules if they are modified:
```bash
# auditctl -R /etc/audit/audit.rules
```


Configure Log Rotation
======================

Like the Windows OS, Linux Auditd is designed to manage the log trail size based upon a specified size. It does not offer the capabilility
out-of-the-box to retain the last X days of logs online. It is expected and mandated that security logs be relayed in near real-time to
a centralized logging service (SIEM) for archiving and processing. Local online log storage is not intended for keeping a historical archive.
Additionally, a Log Storm caused by a repeating security event could overflow the disk storage and cause a loss of a service.
Therefore it is necessary to budget an amount of disk space in /var/log/audit for storing Auditd logs.

By default, the /etc/audit/auditd.conf in this package budgets for 1GB of disk space:
```
# Budget 1GB for total size size (128M * 8)
# Logs will cycle 
max_log_file = 128
num_logs = 8
```

The package defaults to ROTATE to cycle through the log files by overwriting them:
```
## Configure auditd max_log_file_action Upon Reaching Maximum Log Size
## The default action to take when the logs reach their maximum size is to rotate the log files, discarding the oldest one.
## Possible values for ACTION are described in the auditd.conf man page. These include:
## ignore
## syslog
## suspend
## rotate
## keep_logs
## Set the ACTION to rotate to ensure log rotation occurs. This is the default. The setting is case-insensitive.

## Automatically rotating logs (by setting this to rotate) minimizes the chances of the system unexpectedly running out of
## disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use
## external processes to transfer it and reclaim space, keep_logs can be employed.

max_log_file_action = ROTATE
```

To configure auditd log rotation by scheduling Linux auditd service to rotate its logs every day at midnight:

```bash
# tee "/etc/cron.d/auditd" > /dev/null 2>&1 <<< "0 0 * * * root /bin/bash -lc 'service auditd rotate' > /dev/null 2>&1"
```

Test log rotation:
```bash
# ls -la /var/log/audit/
# tail -f /var/log/messages &
# service auditd rotate
```


View Hourly Statistics
======================

To view the number of audit records per hour by key in the last 24 hours, run the provided script:
```bash
 ./hourlystats.py
```

Sample output:
```
Processing file: /var/log/audit/audit.log.4
Processing file: /var/log/audit/audit.log.3
Processing file: /var/log/audit/audit.log.2
Processing file: /var/log/audit/audit.log.1
Processing file: /var/log/audit/audit.log
Key                                         00        01        02        03        04        05        06        07        08        09        10        11        12        13        14        15        16        17        18        19        20        21        22        23    
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
audit_rules_usergroup_modification      0         0         0         0         0         0         0         0         0         0         0         0         10        0         0         0         0         0         0         0         0         0         0         0         
delete                                  0         0         0         0         0         0         0         0         0         0         0         0         4291      9953      0         0         0         0         0         0         0         0         0         0         
execall                                 0         0         0         0         0         0         0         0         0         0         0         0         482       1966      0         0         0         0         0         0         0         0         0         0         
execpriv                                0         0         0         0         0         0         0         0         0         0         0         0         0         1         0         0         0         0         0         0         0         0         0         0         
logins                                  0         0         0         0         0         0         0         0         0         0         0         0         6         3         0         0         0         0         0         0         0         0         0         0         
perm_mod                                0         0         0         0         0         0         0         0         0         0         0         0         12112     805       0         0         0         0         0         0         0         0         0         0         
session                                 0         0         0         0         0         0         0         0         0         0         0         0         4         0         0         0         0         0         0         0         0         0         0         0         
system-locale                           0         0         0         0         0         0         0         0         0         0         0         0         0         620       0         0         0         0         0         0         0         0         0         0         
time-change                             0         0         0         0         0         0         0         0         0         0         0         0         8         30        0         0         0         0         0         0         0         0         0         0         
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Total                                   0         0         0         0         0         0         0         0         0         0         0         0         16913     13378     0         0         0         0         0         0         0         0         0         0        
```

Prerequisites:
Python must be setup to run this script, for example:

```bash
sudo yum update -y
sudo yum install -y epel-release
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python36-devel libjpeg-devel zlib-devel
sudo yum install -y python3-pip
```

As a non-root user:
```bash
pip3 install matplotlib
```

Complementary Controls
======================

RHEL 8: Ensure Sudo Logfile Exists - sudo logfile - CCE-83601-5

By default, RHEL and Oracle Linux do not create the logfile that succinctly records each command that is executed with sudo.
The following setting will effectively duplicate the logging of the Linux auditd rules provided in this package.

To apply the change:
```bash
sudo visudo
Defaults logfile="/var/log/sudo.log"
```

Verify the configuration:
```bash
sudo visudo -c
```

Run a test to verify sudo commands are being logged:
```bash
sudo ls /root
tail -n 10 /var/log/sudo.log
```

To configure log rotation for this file:
```bash
# vi /etc/logrotate.d/sudo

/var/log/sudo.log {
    daily                   # Rotate logs on a daily basis
    rotate 8                # Keep at least 7 days of logs
    compress                # Compress old log files
    delaycompress           # Delay compression until the next rotation
    notifempty              # Do not rotate the log if it is empty
    missingok               # Continue without error if the log file is missing
    postrotate
        /usr/bin/killall -HUP rsyslogd # Send a SIGHUP to rsyslogd to reopen log files
    endscript
}

# chmod 655 /etc/logrotate.d/sudo
```

RHEL 8: Set SSH Daemon LogLevel to VERBOSE - CCE-82420-1

VERBOSE mode will log details of the SSH public key that was used to authenticate - the fingerprint, the key length, and the type of key.
This is strongly advised when multiple keys are stored in authorized_keys for an account that is shared.

To apply the change:
```bash
# vi /etc/ssh/sshd_config
LogLevel VERBOSE

# systemctl restart sshd
```

To verify that fingerprints of authentication keys are being logged, establish a new SSH session, and in the first session run:
```bash
# grep "Accepted key" /var/log/secure
```


The SSHD log /var/log/secure is already covered by syslog rotation:
```bash
# vi /etc/logrotate.d/syslog
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    missingok
    sharedscripts
    postrotate
        /usr/bin/systemctl -s HUP kill rsyslog.service >/dev/null 2>&1 || true
    endscript
}
```

The system default logrotate settings will apply. For example:
```bash
# cat /etc/logrotate.conf
# see "man logrotate" for details
# rotate log files weekly
weekly

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# uncomment this if you want your log files compressed
#compress

# RPM packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.
```

An example to configure custom settings for syslog to retain only 1 week:
```bash
# vi /etc/logrotate.d/syslog
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
/var/log/boot.log {
    missingok
    daily
    rotate 8
    compress
    delaycompress
    notifempty
    create 0640 root utmp
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/syslogd.pid 2>/dev/null) 2> /dev/null || true
    endscript
}
```
