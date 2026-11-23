#!/usr/bin/env python3
"""Test send_report with fixture credentials and a curl stub; send no messages.

Run on Linux with Bash, Python 3, OpenSSL and the standard shell tools:
    python3 tests/test_dingtalk_reporter.py support_parameter_report_traffic_to_dingtalk.sh

The root-only account/config operations and network request are stubbed.
Tests inspect the generated payload and propagate simulated curl/API errors.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text().split("\nwhile true; do\n", 1)[0]
with tempfile.TemporaryDirectory(prefix="dingtalk-reporter-test-") as temporary:
    root = Path(temporary)
    (root / "bin").mkdir()
    config = root / "config"
    config.write_text(
        "DINGTALK_WEBHOOK='https://oapi.dingtalk.com/robot/send?access_token=FIXTURE'\n"
        "DINGTALK_SECRET='SEC_FIXTURE'\n"
        "TRAFFIC_INTERFACE='eth0'\nUPLOAD_LIMIT_GIB='180'\n"
    )
    source = source.replace("/etc/default/traffic-usage-dingtalk-report", str(config))
    source = source.replace("/root/traffic-usage-dingtalk-logs", str(root / "logs"))
    source += "\nsend_report\n"
    script = root / "report.sh"
    script.write_text(source)
    stubs = {
        "getent": "#!/bin/sh\nprintf 'traffic-dingtalk:x:12345:12345::/nonexistent:/usr/sbin/nologin\\n'\n",
        "vnstat": "#!/bin/sh\nprintf '1;eth0;day;1;1;2;0;2026-11;1;194244676883;194244676884;0;1;1;2\\n'\n",
        "ufw": "#!/bin/sh\nprintf 'Status: active\\n'\n",
        "systemctl": "#!/bin/sh\nprintf 'active\\n'\n",
        "runuser": """#!/usr/bin/python3
import os, pathlib, subprocess, sys
assert sys.argv[1:5] == ['-u', 'traffic-dingtalk', '--', 'curl'], sys.argv
pathlib.Path(os.environ['REPORT_TEST_ROOT'], 'sender').write_text('traffic-dingtalk')
sys.exit(subprocess.call(sys.argv[4:]))
""",
        "curl": """#!/usr/bin/python3
import json, os, pathlib, sys
args=sys.argv[1:]
assert args[:6] == ['--noproxy', '*', '--connect-timeout', '10', '--max-time', '30'], args
payload=json.loads(args[args.index('-d')+1])
assert payload['msgtype'] == 'markdown'
assert '- UFW: active' in payload['markdown']['text']
assert '- Upload remaining: 0 B' in payload['markdown']['text']
assert 'timestamp=' in args[-1] and 'sign=' in args[-1]
pathlib.Path(os.environ['REPORT_TEST_ROOT'], 'payload').write_text(json.dumps(payload))
print(os.environ['REPORT_TEST_RESPONSE'])
sys.exit(int(os.environ.get('REPORT_TEST_CURL_RC', '0')))
""",
    }
    for name, text in stubs.items():
        path = root / "bin" / name
        path.write_text(text)
        path.chmod(0o755)
    scenarios = [
        ("accepted", '{"errcode":0,"errmsg":"ok"}', 0, 0),
        ("DNS failure", "", 6, 6),
        ("timeout", "", 28, 28),
        ("HTTP failure", "", 22, 22),
        ("API rejected", '{"errcode":310000,"errmsg":"rejected"}', 0, 1),
        ("missing API code", '{"errmsg":"ok"}', 0, 1),
        ("invalid JSON", "not JSON", 0, 1),
    ]
    for name, response, curl_rc, expected in scenarios:
        env = dict(os.environ, PATH=str(root / "bin") + ":" + os.environ["PATH"],
                   REPORT_TEST_ROOT=str(root), REPORT_TEST_RESPONSE=response,
                   REPORT_TEST_CURL_RC=str(curl_rc))
        result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
        assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)
        assert (root / "sender").read_text() == "traffic-dingtalk"
        assert ("DingTalk report accepted" in result.stdout) == (expected == 0)
        print(f"PASS {name}: rc={result.returncode}, request runs as traffic-dingtalk")
print("No real DingTalk requests were sent by these tests.")
