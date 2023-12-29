# linux_auditd

Description
===========
This repo provides the best practice configuration for Linux auditd for CIS and STIG standards for RedHat and Oracle Linux.

These files are copied to /et/audit to replace existing files.

To generate the rules file:
===========================

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

Configure Log Rotation
======================
