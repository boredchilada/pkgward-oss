from setuptools import setup

setup(
    name="realmod-helper",
    version="1.0.0",
    packages=["helper"],
    package_data={"helper": ["_pytransform.so", "_pytransform.dll", "pytransform/*"]},
)
