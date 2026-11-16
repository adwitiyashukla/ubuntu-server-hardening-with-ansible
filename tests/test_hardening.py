import os
import re
from pathlib import Path

import paramiko
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = yaml.safe_load((ROOT / "group_vars" / "all.yml").read_text())
LAB = ROOT / ".lab"
ADMIN = SETTINGS["admin_user"]
EXPECTED_LOGIN = os.environ.get("LAB_LOGINS", "refused")


def try_login(user, **credentials):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            "127.0.0.1",
            port=2222,
            username=user,
            allow_agent=False,
            look_for_keys=False,
            timeout=30,
            **credentials,
        )
    except paramiko.AuthenticationException:
        return "refused"
    finally:
        client.close()
    return "allowed"


def active_lines(host, path):
    lines = host.file(path).content_string.splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def sshd_settings(host):
    output = host.check_output("sshd -T -C user=%s,host=lab,addr=127.0.0.1" % ADMIN)
    return dict(line.split(" ", 1) for line in output.splitlines() if " " in line)


def test_sshd_effective_settings(host):
    sshd = sshd_settings(host)
    assert sshd["permitrootlogin"] == "no"
    assert sshd["passwordauthentication"] == "no"
    assert sshd["kbdinteractiveauthentication"] == "no"
    assert sshd["pubkeyauthentication"] == "yes"
    assert sshd["permitemptypasswords"] == "no"
    assert sshd["disableforwarding"] == "yes"
    assert sshd["x11forwarding"] == "no"
    assert sshd["banner"] == "/etc/issue.net"
    assert sshd["allowgroups"] == SETTINGS["ssh_group"]
    assert sshd["loglevel"] == SETTINGS["ssh_log_level"]
    assert sshd["maxauthtries"] == str(SETTINGS["ssh_max_auth_tries"])
    assert sshd["maxsessions"] == str(SETTINGS["ssh_max_sessions"])
    assert sshd["logingracetime"] == str(SETTINGS["ssh_login_grace_time"])
    assert sshd["clientaliveinterval"] == str(SETTINGS["ssh_client_alive_interval"])
    assert sshd["clientalivecountmax"] == str(SETTINGS["ssh_client_alive_count_max"])


@pytest.mark.parametrize(
    "option,setting",
    [("ciphers", "ssh_ciphers"), ("macs", "ssh_macs"), ("kexalgorithms", "ssh_kex")],
)
def test_sshd_crypto(host, option, setting):
    assert sshd_settings(host)[option] == ",".join(SETTINGS[setting])


def test_admin_user_is_in_ssh_group(host):
    assert SETTINGS["ssh_group"] in host.user(ADMIN).groups


def test_firewall_rules(host):
    status = host.check_output("ufw status verbose")
    assert "Status: active" in status
    assert "deny (incoming)" in status
    assert "allow (outgoing)" in status
    assert re.search(r"^22/tcp\s+LIMIT IN\s+Anywhere", status, re.MULTILINE)


def test_only_ssh_listens_beyond_loopback(host):
    addresses = [line.split()[3] for line in host.check_output("ss -Htln").splitlines()]
    exposed = {address for address in addresses if not address.startswith(("127.", "[::1]"))}
    assert exposed <= {"0.0.0.0:22", "[::]:22", "*:22"}


@pytest.mark.parametrize("key,value", sorted(SETTINGS["sysctl_settings"].items()))
def test_kernel_setting(host, key, value):
    assert host.sysctl(key) == value


@pytest.mark.parametrize("module", SETTINGS["blocked_kernel_modules"])
def test_kernel_module_blocked(host, module):
    assert host.check_output("modprobe -n -v %s" % module).splitlines()[-1].strip() == "install /bin/false"
    loaded = [line.split()[0] for line in host.check_output("lsmod").splitlines()]
    assert module.replace("-", "_") not in loaded


@pytest.mark.parametrize("path", ["/tmp", "/dev/shm"])
def test_mount_options(host, path):
    mount = host.mount_point(path)
    assert mount.exists
    assert set(SETTINGS["tmp_mount_options"]) <= set(mount.options)


def test_boot_options(host):
    cmdline = host.file("/proc/cmdline").content_string.split()
    assert set(SETTINGS["grub_cmdline_extra"]) <= set(cmdline)


def test_core_dumps_off(host):
    assert host.check_output("su - %s -c 'ulimit -Hc'" % ADMIN) == "0"


def test_apparmor_on(host):
    assert host.check_output("aa-enabled") == "Yes"
    assert host.service("apparmor").is_enabled


def test_audit_rules_loaded(host):
    assert host.service("auditd").is_running
    assert host.service("auditd").is_enabled
    rules = host.check_output("auditctl -l")
    keys = [
        "scope",
        "sudo_log_file",
        "time-change",
        "system-locale",
        "identity",
        "logins",
        "session",
        "MAC-policy",
        "user_emulation",
        "perm_mod",
        "access",
        "mounts",
        "delete",
        "kernel_modules",
        "privileged",
    ]
    for key in keys:
        assert re.search(r"(-k |key=)%s\b" % re.escape(key), rules), key


def test_audit_rules_locked(host):
    expected = "enabled 2" if SETTINGS["audit_immutable"] else "enabled 1"
    assert expected in host.check_output("auditctl -s")


def test_file_integrity_baseline(host):
    if not SETTINGS["aide_enabled"]:
        pytest.skip("aide is turned off in the settings")
    assert host.file("/var/lib/aide/aide.db").exists
    assert host.service("dailyaidecheck.timer").is_enabled


def test_pam_stack(host):
    auth = "\n".join(active_lines(host, "/etc/pam.d/common-auth"))
    assert "pam_faillock.so preauth" in auth
    assert "pam_faillock.so authfail" in auth
    assert "nullok" not in auth
    password = "\n".join(active_lines(host, "/etc/pam.d/common-password"))
    order = [password.index(name) for name in ("pam_pwquality.so", "pam_pwhistory.so", "pam_unix.so")]
    assert order == sorted(order)
    assert "remember=%d" % SETTINGS["password_remember"] in password
    assert "yescrypt" in password


@pytest.mark.parametrize(
    "path,option,setting",
    [
        ("/etc/security/pwquality.conf", "minlen", "password_min_length"),
        ("/etc/security/pwquality.conf", "minclass", "password_min_classes"),
        ("/etc/security/pwquality.conf", "maxrepeat", "password_max_repeat"),
        ("/etc/security/pwquality.conf", "maxsequence", "password_max_sequence"),
        ("/etc/security/pwquality.conf", "difok", "password_diff_chars"),
        ("/etc/security/faillock.conf", "deny", "faillock_deny"),
        ("/etc/security/faillock.conf", "unlock_time", "faillock_unlock_time"),
    ],
)
def test_password_rule(host, path, option, setting):
    assert "%s = %d" % (option, SETTINGS[setting]) in active_lines(host, path)


def test_password_aging_defaults(host):
    defaults = dict(line.split()[:2] for line in active_lines(host, "/etc/login.defs"))
    assert defaults["PASS_MAX_DAYS"] == str(SETTINGS["password_max_days"])
    assert defaults["PASS_MIN_DAYS"] == str(SETTINGS["password_min_days"])
    assert defaults["PASS_WARN_AGE"] == str(SETTINGS["password_warn_days"])
    assert defaults["ENCRYPT_METHOD"] == "YESCRYPT"
    assert defaults["UMASK"] == SETTINGS["default_umask"]
    assert "INACTIVE=%d" % SETTINGS["password_inactive_days"] in active_lines(host, "/etc/default/useradd")


def test_admin_password_aging(host):
    fields = host.check_output("getent shadow %s" % ADMIN).split(":")
    if not fields[1].startswith("$"):
        pytest.skip("the admin user has no password")
    expected = [SETTINGS[name] for name in ("password_min_days", "password_max_days", "password_warn_days", "password_inactive_days")]
    assert fields[3:7] == [str(value) for value in expected]


def test_shell_timeout_and_umask(host):
    output = host.check_output("su - %s -c 'echo $TMOUT; umask'" % ADMIN)
    assert output.split() == [str(SETTINGS["shell_timeout"]), "0" + SETTINGS["default_umask"]]


def test_sudo_is_logged(host):
    assert 'Defaults logfile="/var/log/sudo.log"' in active_lines(host, "/etc/sudoers.d/50-hardening")
    assert "COMMAND=" in host.file("/var/log/sudo.log").content_string


def test_su_is_restricted(host):
    assert "auth       required   pam_wheel.so use_uid group=sugroup" in active_lines(host, "/etc/pam.d/su")
    assert host.check_output("getent group sugroup").split(":")[3] == ""


@pytest.mark.parametrize("path", ["/etc/issue", "/etc/issue.net", "/etc/motd"])
def test_banner(host, path):
    assert host.file(path).content_string.strip() == SETTINGS["banner_text"]


@pytest.mark.parametrize(
    "path,group,mode",
    [
        ("/etc/passwd", "root", 0o644),
        ("/etc/group", "root", 0o644),
        ("/etc/shadow", "shadow", 0o640),
        ("/etc/gshadow", "shadow", 0o640),
        ("/etc/crontab", "root", 0o600),
        ("/etc/cron.d", "root", 0o700),
        ("/etc/cron.daily", "root", 0o700),
        ("/etc/cron.allow", "crontab", 0o640),
        ("/etc/ssh/sshd_config", "root", 0o600),
        ("/etc/ssh/sshd_config.d/10-hardening.conf", "root", 0o600),
        ("/boot/grub/grub.cfg", "root", 0o600),
    ],
)
def test_file_permissions(host, path, group, mode):
    target = host.file(path)
    assert (target.user, target.group, target.mode) == ("root", group, mode)


@pytest.mark.parametrize("path", ["/var/log/syslog", "/var/log/auth.log", "/var/log/dpkg.log", "/var/log/sudo.log"])
def test_log_file_closed_to_others(host, path):
    assert host.file(path).mode & 0o007 == 0


def test_home_folder_closed_to_others(host):
    home = host.user(ADMIN).home
    assert host.file(home).mode & 0o007 == 0
    assert host.check_output("find %s -maxdepth 1 -type f -name '.*' -perm /g+wx,o+rwx" % home) == ""


@pytest.mark.parametrize("name", SETTINGS["remove_packages"])
def test_package_removed(host, name):
    assert not host.package(name).is_installed


def test_automatic_updates_on(host):
    assert host.package("unattended-upgrades").is_installed
    periodic = host.check_output("apt-config dump APT::Periodic")
    assert 'APT::Periodic::Update-Package-Lists "1";' in periodic
    assert 'APT::Periodic::Unattended-Upgrade "1";' in periodic


def test_time_sync(host):
    service = host.service("systemd-timesyncd")
    assert service.is_running
    assert service.is_enabled
    servers = host.check_output("timedatectl show-timesync --property=SystemNTPServers --value")
    assert servers.split() == SETTINGS["time_servers"]


def test_journal_is_kept_on_disk(host):
    assert "Storage=persistent" in active_lines(host, "/etc/systemd/journald.conf")
    assert host.file("/var/log/journal").is_directory


def test_node_exporter_serves_metrics_on_localhost(host):
    port = SETTINGS["node_exporter_port"]
    service = host.service("prometheus-node-exporter")
    assert service.is_running
    assert service.is_enabled
    assert host.socket("tcp://127.0.0.1:%d" % port).is_listening
    assert "node_uname_info" in host.check_output("curl -sf http://127.0.0.1:%d/metrics" % port)


def test_node_exporter_is_sandboxed(host):
    report = host.check_output("systemd-analyze security --no-pager prometheus-node-exporter.service")
    exposure = float(re.search(r"Overall exposure level for \S+: ([0-9.]+)", report).group(1))
    assert exposure < 3


def test_password_login():
    password = (LAB / "password").read_text().strip()
    assert try_login(ADMIN, password=password) == EXPECTED_LOGIN


def test_root_login_with_valid_key():
    assert try_login("root", key_filename=str(LAB / "id_ed25519")) == EXPECTED_LOGIN
