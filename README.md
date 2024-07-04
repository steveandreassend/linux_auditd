# linux_auditd

Description
===========
This repo provides as a reference the best practice configuration for Linux auditd logging by harmonizing the CIS and STIG standards for RedHat and Oracle Linux.

The CIS (Center for Internet Security) produces various cyber security related services. In particular, it produces benchmarks, which are “configuration guidelines for various technology groups to safeguard systems against today evolving cyber threat" in the words of the CIS.

Security Technical Implementation Guides are published as a tool to improve the security of Department of Defense (DOD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents.

References
==========
* [Center for Internet Security (CIS) compliance in Red Hat Enterprise Linux using OpenSCAP](https://www.redhat.com/en/blog/center-internet-security-cis-compliance-red-hat-enterprise-linux-using-openscap)
* [Red Hat Enterprise Linux 8 (3.0.0)](https://www.cisecurity.org/benchmark/red_hat_linux)
* [Red Hat Enterprise Linux 8 Security Technical Implementation Guide](https://www.stigviewer.com/stig/red_hat_enterprise_linux_8/2023-09-11/MAC-1_Classified/)

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

Load the rules into the audit system:
```bash
   # auditctl -R /etc/audit/audit.rules
```

Restarting auditd will activate the rules:
```bash
# systemctl restart auditd
# systemctl status auditd
```

List the configured rules:
```bash
# sudo auditctl -l
```

Configure Log Rotation
======================

To configure the Linux auditd service to rotate its logs on a daily basis, keeping only the latest 31 files (as per num_logs setting in auditd.conf):

```bash
sudo cp -pv /usr/share/doc/audit-*/auditd.cron /etc/cron.daily/
sudo chmod -v +x /etc/cron.daily/auditd.cron
```

Configure auditd log rotation by scheduling Linux auditd service to rotate its logs every day at midnight:

```bash
sudo tee "/etc/cron.d/auditd" > /dev/null 2>&1 <<< "0 0 * * * root /bin/bash -lc 'service auditd rotate' > /dev/null 2>&1"
```

The Linux auditd service controls only the size of its logs, but not the age of the logs, hence for controlling the retention period. Therefore it is necessary
in the /etc/audit/auditd.conf file to disable log rotation based on file size (set max_log_file_action to IGNORE) and set num_logs to the number of days to keep + 1:

```
max_log_file_action = IGNORE
num_logs = 31
```

In the example above, the intent is to keep 30 days of Audit logging, hence it was set to 31 logs:
  30 days of archive + 1 log referring to the current day.

The duration of online log retention will be mandated by your enterprise's CISO. Logs are typically relayed to a SIEM service where they are processed, rather than on the host.
