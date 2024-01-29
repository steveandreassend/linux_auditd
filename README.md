# linux_auditd

Description
===========
This repo provides as a reference the best practice configuration for Linux auditd by harmonizing the CIS and STIG standards for RedHat and Oracle Linux. These files can be copied to /etc/audit/ to replace existing files.

The CIS (Center for Internet Security) produces various cyber security related services. In particular, it produces benchmarks, which are “configuration guidelines for various technology groups to safeguard systems against today evolving cyber threat" in the words of the CIS.

Security Technical Implementation Guides are published as a tool to improve the security of Department of Defense (DOD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents.

Additionally it includes rules to track the Break Glass activity of Linux OS users by recording all OS commands executed. This is useful on database servers where DBAs exceptionally login into the Linux OS with approved access to run commands to perform tasks for planned and unplanned maintenance.

References
==========
* [Center for Internet Security (CIS) compliance in Red Hat Enterprise Linux using OpenSCAP](https://www.redhat.com/en/blog/center-internet-security-cis-compliance-red-hat-enterprise-linux-using-openscap)
* [Red Hat Enterprise Linux 8 (3.0.0)](https://www.cisecurity.org/benchmark/red_hat_linux)
* [Red Hat Enterprise Linux 8 Security Technical Implementation Guide](https://www.stigviewer.com/stig/red_hat_enterprise_linux_8/2023-09-11/MAC-1_Classified/)

List of Rules:
===========================
The following rules files exist:
* MAC_policy.rules:
* access.rules:
* actions.rules:
* activity.rules: This tracks Break Glass activities outside the CIS and STIG baselines.
* audit.rules:
* audit_rules_usergroup_modification.rules:
* delete.rules:
* finalize.rules:
* logins.rules: This tracks all login (successful and unsuccessful) and logout events.
* modules.rules:
* mounts.rules:
* perm_mod.rules:
* privileged.rules:
* setgid.rules:
* setuid.rules:
* system_local.rules: This tracks all activity that modify system parameters such as the hostname.
* time_change.rules: This tracks all activity that changes the sytem time.

To view logs that match these records, use the key which matches the *.rules filename.
```bash
   # ausearch -k logins
```

To generate the rules file:
===========================

The augenrules script reads rules located in the /etc/audit/rules.d/ directory and compiles them into an audit.rules file. This script processes all files that end with .rules in a specific order based on their natural sort order. The files in this directory are organized into groups with the following meanings:

10 Kernel and auditctl configuration
20 Rules that could match general rules but you want a different match
30 Main rules
40 Optional rules
50 Server-specific rules
70 System local rules
90 Finalize (immutable)

```bash
   # augenrules --load
```

 
 
The `/etc/audit/rules.d` directory contains separate files that define individual audit rules.
To generate the consolidated `audit.rules` file from these individual rule files, you can use the `auditctl` command.
Remember, changes made to the audit rules won't take effect until you reload them using `auditctl`. Additionally, ensure that the rules in the individual files (`/etc/audit/rules.d/*.rules`) are properly formatted and valid audit rules; otherwise, errors might occur when loading the rules into the audit system.

1. Concatenate the rules from files in `/etc/audit/rules.d`:
   
   You can use the `cat` command to concatenate the rules from all the files within `/etc/audit/rules.d` into a single file.
```bash
   # cat /etc/audit/rules.d/*.rules > /etc/audit/audit.rules
```
   This command reads all files with a `.rules` extension in `/etc/audit/rules.d` and appends their contents to the `audit.rules` file in `/etc/audit`.

2. Load the rules into the audit system:

   Once you've consolidated the rules into `audit.rules`, you need to load them into the kernel using the `auditctl` command.
```bash
   # auditctl -R /etc/audit/audit.rules
```
   This command loads the rules from the `audit.rules` file into the running audit system.

Activate Rules
======================
```bash
   $ sudo systemctl restart auditd
   $ sudo systemctl status auditd
```

Configure Log Rotation
======================

To configure the Linux auditd service to rotate its logs on a daily basis, keeping only the latest 31 files (as per num_logs setting in auditd.conf):

```bash
sudo cp -pv /usr/share/doc/audit-*/auditd.cron /etc/cron.daily/
sudo chmod -v +x /etc/cron.daily/auditd.cron
```

Configure auditd log rotation by scheduling Linux auditd service to rotate its logs every day at midnight.

```bash
sudo tee "/etc/cron.d/auditd" > /dev/null 2>&1 <<< "0 0 * * * root /bin/bash -lc 'service auditd rotate' > /dev/null 2>&1"
```

The Linux auditd service controls only the size of its logs, but not the age of the logs, hence for controlling the retention period. Therefore it is necessary in the /etc/audit/auditd.conf file to disable log rotation based on file size (set max_log_file_action to IGNORE) and set num_logs to the number of days to keep + 1:

```
max_log_file_action = IGNORE
num_logs = 31
```

In the example above, the intent is to keep 30 days of Audit logging, hence it was set to 31 logs:
  30 days of archive + 1 log referring to the current day.

The duration of online log retention will be mandated by your enterprise's CISO. Logs are typically archived to a SIEM service where they are processed, rather than on the host.
