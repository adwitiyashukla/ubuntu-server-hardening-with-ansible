# ubuntu-server-hardening-with-ansible

An Ansible playbook that takes a fresh Ubuntu 24.04 server and hardens it. It covers SSH, the firewall, kernel settings, accounts and passwords, audit logging, file integrity checks and a sandboxed node_exporter.

I did not want to just claim the server is hardened, so the repo also has a lab that proves it. CI boots a throwaway Ubuntu 24.04 VM, scores it with OpenSCAP and Lynis, runs the playbook twice, reboots the VM, runs 107 tests against it and then scores it again.

## Results

Measured in CI on the official Ubuntu 24.04 cloud image (run 1, 16 Nov 2026). The lab VM starts out like a typical fresh VPS, with password login and root login over SSH both turned on.

| Measure | Before | After |
| --- | --- | --- |
| CIS Level 1 Server checks passing | 230 of 340 (67.6%) | 343 of 355 (96.6%) |
| Lynis hardening index | 60 | 79 |
| node_exporter exposure score (systemd-analyze security) | 9.0 UNSAFE | 1.0 OK |

| Check | Result |
| --- | --- |
| First playbook run | 323 seconds |
| Changes made by the second run | 0 |
| Tests passing after a reboot | 107 of 107 |

The CIS totals are different before and after because some checks only apply once the thing they check exists. For example, the 12 password quality checks only count once libpam-pwquality is installed, and the 3 /tmp mount checks only count once /tmp is its own mount.

12 CIS checks still fail after hardening. These are either choices I made or quirks of the check itself:

| Check | Why it still fails |
| --- | --- |
| set_ufw_default_rule | Outgoing traffic is allowed on purpose, so apt, DNS and time sync work without a list of allowed ports. |
| ufw_rules_for_open_ports | The check only skips 127.0.0.1 and ::1, so it trips on the systemd-resolved DNS stub at 127.0.0.54. That is loopback too, and the tests show port 22 is the only port open beyond loopback. |
| nftables_rules_permanent, set_nftables_table, set_nftables_loopback_traffic | These nftables checks still run even though ufw is picked as the firewall. |
| grub2_password, grub2_uefi_password | I did not set a GRUB password. On a cloud VM nobody sits at the boot menu. |
| package_rsync_removed | rsync stays installed as a tool. Its daemon is masked, so nothing listens. |
| root_path_all_dirs | The PATH root gets includes /snap/bin, which does not exist until a snap is installed. |
| all_apparmor_profiles_in_enforce_complain_mode | Ubuntu 24.04 ships a few AppArmor profiles in unconfined mode on purpose, so apps like browsers can use user namespaces. |
| aide_build_database | The AIDE database is there (a test checks it), but the check cannot read its path from the Ubuntu aide.conf. |
| file_ownerships_var_log | AIDE writes its own logs as its _aide user, and the check only allows root or syslog. |

## What the playbook does

There is one role for each area. They run in this order.

| Role | What it changes |
| --- | --- |
| base | Turns on automatic security updates, removes packages a server does not need (telnet, ftp, rsh, nis, talk, prelink, apport), sets the time servers, writes login banners, limits cron to root, masks the rsync daemon and fixes the permissions of the account files. |
| accounts | Password aging (365 days max, 1 day min, 7 days warning, lock after 45 days unused), yescrypt hashes, passwords of 14 or more characters with all 4 character types, lockout for 15 minutes after 4 failed logins, the last 24 passwords cannot be reused, no empty passwords, su only for an empty group, sudo logged to /var/log/sudo.log, a 15 minute shell timeout and umask 027. |
| ssh | Keys only, no root login, only members of the sshusers group, strong ciphers, MACs and key exchange, and forwarding turned off. The config is checked with sshd -t before sshd reloads it. |
| firewall | ufw blocks incoming and routed traffic by default and rate limits SSH. It also drops loopback addresses that show up on other interfaces and keeps martian packet logging on. |
| kernel | 34 sysctl settings for the network stack and memory, 10 unused kernel modules blocked, /tmp and /dev/shm mounted with nodev, nosuid and noexec, core dumps off, AppArmor and audit options on the kernel command line, and the GRUB config readable by root only. |
| monitoring | node_exporter listening on 127.0.0.1:9100 only, sandboxed with a systemd drop-in. |
| audit | Journal kept on disk, auditd rules for identity files, sudo, time changes, kernel modules and every setuid and setgid program, rules locked until the next reboot, and an AIDE file baseline with a daily check. Log files are closed to other users. |

Every setting lives in group_vars/all.yml. Before it changes anything, site.yml checks each setting for the right type and range and stops if one is off.

## How the lab works

lab.sh does the whole run.

1. Downloads the official Ubuntu 24.04 cloud image and checks it against the published SHA256SUMS.
2. Boots it in QEMU with cloud-init, with password login and root login over SSH turned on.
3. Logs in with a password and as root to show both work before hardening.
4. Scores the VM with OpenSCAP (CIS Level 1 Server) and Lynis.
5. Runs the playbook, then runs it again. The second run has to change nothing.
6. Reboots the VM, so the tests prove the settings survive a reboot.
7. Runs the pytest and testinfra suite. The password and root logins from step 3 now have to be refused.
8. Scores the VM again and prints the tables above.

The CIS content is the ubuntu2404 SCAP datastream from Ubuntu's own ssg-debderived 0.1.79 package, and its checksum is pinned in lab.sh. CIS lets you choose ufw, nftables or iptables as the firewall, so the scan tells the profile that ufw is the one in use.

The node_exporter score compares the unit file from the Ubuntu package with the same file plus the sandbox drop-in. Both are scored with systemd-analyze security, the same way.

## Run it

You need Linux (or WSL2) with QEMU, KVM, cloud-image-utils and Python 3.12 or newer. Without KVM, QEMU falls back to software emulation, which is a lot slower.

```
pip install -r requirements.txt
bash lab.sh all
```

The steps can also be run one at a time with bash lab.sh up, harden, reboot, check, scan before, scan after, ssh and down.

To harden a real server, put its address, user and key in inventory.ini, change group_vars/all.yml if you need to, and run:

```
ansible-playbook site.yml
```

Password login and root login get turned off, so make sure the user in admin_user has a working SSH key first. The playbook only runs on Ubuntu 24.04 and stops on anything else.
