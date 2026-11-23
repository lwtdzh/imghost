#!/usr/bin/env python3
"""Exercise the traffic script using UFW's real parser and file writer.

Run as root on Linux with UFW and IPv4/IPv6 restore tools installed:
    sudo python3 tests/test_traffic_limit_ufw.py support_parameter_adjust_ufw_by_traffic_limit.sh

All rule edits, status, counters and state live in temporary directories.
Live UFW commands and account lookups are stubbed. The script's real
iptables-restore --test calls validate syntax without applying any rules.
"""
import gettext
import datetime
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys
import tempfile

gettext.install("ufw")
import ufw.backend_iptables
import ufw.common
import ufw.frontend
import ufw.util

ufw.common.do_checks = False
ufw.util.get_iptables_version = lambda _: "1.8.9"
ufw.backend_iptables.UFWBackendIptables.is_enabled = lambda self: False


def frontend(root):
    ui = ufw.frontend.UFWFrontend(False, datadir=str(root))
    ui.backend.caps = {"limit": {"4": False, "6": False}}
    return ui


def execute(root, args):
    ui = frontend(root)
    parsed = ufw.frontend.parse_command(["/usr/sbin/ufw"] + list(args))
    rule = parsed.data.get("rule", "")
    version = parsed.data.get("iptype", "")
    return ui.do_action(parsed.action, rule, version, parsed.force)


def comment(rule):
    return bytes.fromhex(rule.comment).decode("utf-8") if rule.comment else ""


def shim():
    root = Path(os.environ["UFW_TEST_ROOT"])
    args = sys.argv[2:]
    with (root / "commands").open("a") as stream:
        stream.write(" ".join(args) + "\n")
    if args == ["status"]:
        print("Status: " + (root / "status").read_text())
    elif args == ["--force", "enable"]:
        if os.environ.get("UFW_TEST_FAIL_ENABLE"):
            raise SystemExit("Injected enable failure")
        (root / "status").write_text("active")
        print("Fixture firewall enabled")
    elif args == ["--force", "disable"]:
        if os.environ.get("UFW_TEST_FAIL_DISABLE"):
            raise SystemExit("Injected disable failure")
        (root / "status").write_text("inactive")
        print("Fixture firewall disabled")
    elif os.environ.get("UFW_TEST_SKIP_SSH") and args[:2] == ["prepend", "allow"]:
        print("Injected successful command without installing SSH")
    else:
        print(execute(root, args))


def main(source_path):
    source = Path(source_path).read_text()
    harness = Path(__file__).resolve()
    scenarios = [
        ("empty", [], [], "inactive", True),
        ("ssh-only", ["allow 22/tcp"], ["allow 22/tcp"], "inactive", True),
        ("incident", [
            "deny out to any comment traffic-limit:block-out",
            "deny in from any comment traffic-limit:block-in",
            "allow 22/tcp comment traffic-limit:ssh-keepalive",
        ], None, "inactive", True),
        ("unrelated-rules", [
            "allow 443/tcp", "allow in from 192.0.2.0/24 to any port 22 proto tcp",
            "allow out 53/udp",
        ], ["allow 8443/tcp", "allow out 53/udp"], "active", True),
        ("ipv6-ssh-missing", [
            "allow 22/tcp comment traffic-limit:ssh-keepalive",
        ], [], "inactive", True),
        ("ipv6-wrong-order", [
            "allow 22/tcp comment traffic-limit:ssh-keepalive",
            "deny in from any comment traffic-limit:block-in",
        ], [
            "deny in from any comment traffic-limit:block-in",
            "allow 22/tcp comment traffic-limit:ssh-keepalive",
        ], "active", True),
        ("ipv4-only", [], [], "inactive", False),
    ]
    for name, rules4, rules6, initial_status, ipv6 in scenarios:
        with tempfile.TemporaryDirectory(prefix="ufw-order-") as temporary:
            root = Path(temporary)
            (root / "etc/default").mkdir(parents=True)
            shutil.copytree("/etc/ufw", root / "etc/ufw")
            defaults = Path("/etc/default/ufw").read_text()
            if not ipv6:
                defaults = defaults.replace("IPV6=yes", "IPV6=no")
            (root / "etc/default/ufw").write_text(defaults)
            (root / "status").write_text(initial_status)
            (root / "tx").write_text("200")
            (root / "month").write_text(datetime.date.today().strftime("%Y-%m"))
            (root / "vnstat-calls").touch()
            (root / "commands").touch()
            (root / "bin").mkdir()
            (root / "resolv.conf").write_text(
                "nameserver 192.0.2.53\nnameserver 2001:db8::53\n"
            )
            (root / "bin/getent").write_text(
                "#!/bin/sh\nprintf 'traffic-dingtalk:x:12345:12345::/nonexistent:/usr/sbin/nologin\\n'\n"
            )
            (root / "bin/id").write_text("#!/bin/sh\nprintf '12345\\n'\n")
            (root / "bin/ufw").write_text(
                f"#!/bin/sh\nexec /usr/bin/python3 {harness} shim \"$@\"\n"
            )
            (root / "bin/vnstat").write_text(
                "#!/usr/bin/python3\n"
                "import os\nfrom pathlib import Path\n"
                "root=Path(os.environ['UFW_TEST_ROOT'])\n"
                "with (root/'vnstat-calls').open('a') as stream: stream.write('read\\n')\n"
                "if (root/'vnstat-fail').exists(): raise SystemExit('Injected vnStat error')\n"
                "month=(root/'month').read_text()\n"
                "tx=int((root/'tx').read_text())\n"
                "print(';'.join(['1','eth0','day','1','1','2','0',month,"
                "'1',str(tx),str(tx+1),'0','1','1','2']))\n"
            )
            (root / "bin/date").write_text(
                "#!/bin/sh\n"
                'if [ "$1" = "+%Y-%m" ]; then\n'
                '  /bin/cat "$UFW_TEST_ROOT/month"\n'
                'else\n  exec /bin/date "$@"\nfi\n'
            )
            for executable in (root / "bin").iterdir():
                executable.chmod(0o755)
            test_source = source.replace("/etc/ufw/", str(root / "etc/ufw") + "/")
            test_source = test_source.replace("/etc/default/ufw", str(root / "etc/default/ufw"))
            test_source = test_source.replace("/etc/resolv.conf", str(root / "resolv.conf"))
            test_source = test_source.replace("/run/systemd/resolve/resolv.conf", str(root / "missing-resolv.conf"))
            script = root / "script.sh"
            script.write_text(test_source)
            ui = frontend(root)
            ui.backend.rules = []
            ui.backend.rules6 = []
            ui.backend._write_rules(False)
            ui.backend._write_rules(True)
            for version, commands in (("v4", rules4), ("v6", rules4 if rules6 is None else rules6)):
                if version == "v6" and not ipv6:
                    continue
                for command in commands:
                    parsed = ufw.frontend.parse_command(["/usr/sbin/ufw"] + command.split())
                    ui.set_rule(parsed.data["rule"], version)
            original = frontend(root)
            unrelated = [
                [r.format_rule() for r in rules if "traffic-limit:" not in comment(r)
                 and not (r.protocol == "tcp" and r.dport == "22"
                          and r.src in ("0.0.0.0/0", "::/0"))]
                for rules in (original.backend.rules, original.backend.rules6)
            ]
            env = dict(os.environ, UFW_TEST_ROOT=str(root),
                       TRAFFIC_LIMIT_STATE_DIR=str(root / "state"),
                       TRAFFIC_LIMIT_LOCK_FILE=str(root / "lock"),
                       PATH=str(root / "bin") + ":" + os.environ["PATH"])

            def run(*options, expected=0, extra_env=None):
                result = subprocess.run(
                    ["bash", str(script), "--interface", "eth0", "--upload-limit", "100b", *options],
                    env=dict(env, **(extra_env or {})), text=True, capture_output=True,
                )
                if result.returncode != expected:
                    raise AssertionError(f"{name}: rc={result.returncode}\n{result.stdout}\n{result.stderr}")
                return result

            def check(blocked):
                current = frontend(root)
                families = [current.backend.rules]
                if ipv6:
                    families.append(current.backend.rules6)
                for index, rules in enumerate(families):
                    assert rules and rules[0].action == "allow", (name, index)
                    assert rules[0].dport == "22" and rules[0].protocol == "tcp", (name, index)
                    comments = [comment(r) for r in rules]
                    for marker in ("block-in", "block-out"):
                        assert any(marker in c for c in comments) == blocked, (name, comments)
                    remaining = [r.format_rule() for r in rules if "traffic-limit:" not in comment(r)]
                    assert remaining == unrelated[index], (name, remaining, unrelated[index])

            before = [(root / "etc/ufw" / f).read_bytes() for f in ("user.rules", "user6.rules")]
            before_output = {
                filename: re.sub(
                    r"(?m)^# BEGIN traffic-limit:dingtalk-egress\n.*?^# END traffic-limit:dingtalk-egress\n",
                    "", (root / "etc/ufw" / filename).read_text(), flags=re.DOTALL,
                )
                for filename in ("before.rules", "before6.rules")
            }
            run("--dry-run")
            assert before == [(root / "etc/ufw" / f).read_bytes() for f in ("user.rules", "user6.rules")]
            assert not (root / "state/state").exists()
            if name == "empty":
                run(expected=1, extra_env={"UFW_TEST_SKIP_SSH": "1"})
                assert (root / "status").read_text() == "inactive"
                assert "--force enable" not in (root / "commands").read_text()
                # The failed run leaves only fixture block rules and prior state.
            run()
            check(True)
            for version, filename, address in (
                ("ufw", "before.rules", "192.0.2.53"),
                ("ufw6", "before6.rules", "2001:db8::53"),
            ):
                text = (root / "etc/ufw" / filename).read_text()
                assert f"-A {version}-before-output -p tcp --dport 443 -m owner --uid-owner 12345 -j ACCEPT" in text
                for protocol in ("udp", "tcp"):
                    assert f"-A {version}-before-output -d {address} -p {protocol} --dport 53 -j ACCEPT" in text
                assert re.sub(
                    r"(?m)^# BEGIN traffic-limit:dingtalk-egress\n.*?^# END traffic-limit:dingtalk-egress\n",
                    "", text, flags=re.DOTALL,
                ) == before_output[filename]
            assert (root / "status").read_text() == "active"
            state = (root / "state/state").read_text()
            assert state.strip() == f"ufw_was_active={int(initial_status == 'active')}"
            (root / "commands").write_text("")
            run()
            check(True)
            calls = (root / "commands").read_text().splitlines()
            assert all(c in ("show added", "status") for c in calls), (name, calls)
            (root / "tx").write_text("1")
            run()
            check(False)
            assert (root / "status").read_text() == initial_status
            assert not (root / "state/state").exists()
            run()
            check(False)
            (root / "tx").write_text("200")
            run()
            check(True)
            print(f"PASS {name}: dry-run, block, repeat, restore, repeat, block again")

            marker = root / "state/month-unlock"
            quota_state = root / "state/state"
            (root / "month").write_text("2026-11")

            def snapshot():
                paths = [
                    root / "etc/ufw" / filename for filename in
                    ("user.rules", "user6.rules", "before.rules", "before6.rules")
                ] + [root / "status", quota_state, marker]
                return {str(p): p.read_bytes() if p.exists() else None for p in paths}

            saved = snapshot()
            run("--unlock-current-month", "--dry-run")
            assert snapshot() == saved
            run("--unlock-current-month", "--resume-monitoring", expected=1)
            assert snapshot() == saved
            # Opening an active quota block must remember the pre-quota
            # state, not the active state caused by the quota itself.
            if initial_status == "active":
                run("--unlock-current-month", expected=1,
                    extra_env={"UFW_TEST_FAIL_DISABLE": "1"})
                assert marker.exists() and quota_state.exists()
                assert (root / "status").read_text() == "active"
            run("--unlock-current-month")
            check(False)
            expected_marker = (
                f"month=2026-11\nufw_was_active={int(initial_status == 'active')}\n"
            )
            assert marker.read_text() == expected_marker
            assert marker.stat().st_mode & 0o777 == 0o600
            assert not quota_state.exists()
            assert (root / "status").read_text() == "inactive"
            assert (root / "tx").read_text() == "200"
            (root / "vnstat-fail").touch()
            (root / "vnstat-calls").write_text("")
            run()
            run("--unlock-current-month")
            assert marker.read_text() == expected_marker
            assert not (root / "vnstat-calls").read_text()
            (root / "status").write_text("active")
            saved = snapshot()
            run("--dry-run")
            assert snapshot() == saved
            run()
            assert (root / "status").read_text() == "inactive"
            (root / "vnstat-fail").unlink()
            # December's fresh vnStat monthly counter below threshold
            # restores the original firewall state, then checks the quota.
            (root / "month").write_text("2026-12")
            (root / "tx").write_text("1")
            saved = snapshot()
            run("--dry-run")
            assert snapshot() == saved
            if initial_status == "active":
                run(expected=1, extra_env={"UFW_TEST_FAIL_ENABLE": "1"})
                assert marker.exists()
                assert (root / "status").read_text() == "inactive"
            run()
            check(False)
            assert not marker.exists() and not quota_state.exists()
            assert (root / "status").read_text() == initial_status
            # A later December quota violation must still block.
            (root / "tx").write_text("200")
            run()
            check(True)
            assert quota_state.read_text().strip() == f"ufw_was_active={int(initial_status == 'active')}"
            run("--unlock-current-month")
            assert marker.read_text().startswith("month=2026-12\n")
            # December -> January expiry while already over quota.
            (root / "month").write_text("2027-01")
            run()
            check(True)
            assert not marker.exists()
            assert quota_state.read_text().strip() == f"ufw_was_active={int(initial_status == 'active')}"
            run("--unlock-current-month")
            saved = snapshot()
            run("--resume-monitoring", "--dry-run")
            assert snapshot() == saved
            run("--resume-monitoring")
            check(True)
            assert not marker.exists()
            # Cancellation also restores correctly below quota.
            run("--unlock-current-month")
            (root / "tx").write_text("1")
            run("--resume-monitoring")
            check(False)
            assert (root / "status").read_text() == initial_status
            assert not marker.exists() and not quota_state.exists()
            # An unlock before any quota block snapshots current UFW state.
            run("--unlock-current-month")
            assert marker.read_text() == (
                f"month=2027-01\nufw_was_active={int(initial_status == 'active')}\n"
            )
            (root / "month").write_text("2027-02")
            (root / "vnstat-fail").touch()
            run(expected=2)
            check(True)
            assert not marker.exists()
            assert quota_state.read_text().strip() == f"ufw_was_active={int(initial_status == 'active')}"
            (root / "vnstat-fail").unlink()
            (root / "tx").write_text("1")
            run()
            # Corrupt files must never provide a quota bypass or execute
            # contents. Dry-run preserves even malformed files.
            for invalid in (
                "", "month=2027-02\n", "month=2027-13\nufw_was_active=0\n",
                "month=2027-02\nufw_was_active=2\n",
                "month=2027-02\nufw_was_active=0\nextra=yes\n",
                f"month=2027-02\nufw_was_active=$(touch {root / 'injected'})\n",
            ):
                marker.write_text(invalid)
                (root / "tx").write_text("200")
                saved = snapshot()
                run("--dry-run")
                assert snapshot() == saved
                run()
                check(True)
                assert not marker.exists() and not (root / "injected").exists()
                (root / "tx").write_text("1")
                run()
            # Reissuing after expiry starts a new monthly unlock with the
            # original snapshot, even if UFW used to be active.
            run("--unlock-current-month")
            (root / "month").write_text("2027-03")
            run("--unlock-current-month")
            assert marker.read_text() == (
                f"month=2027-03\nufw_was_active={int(initial_status == 'active')}\n"
            )
            run("--resume-monitoring")
            assert (root / "status").read_text() == initial_status
            print(f"PASS {name}: monthly unlock, repeat, dry-run, expiry, year rollover, cancel, vnStat failure, malformed state")
    print("PASS: activation refused when SSH installation does not produce safe rule order")
    print("All tests used isolated rule files; no live firewall rules or accounts were changed.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "shim":
        shim()
    else:
        main(sys.argv[1])
