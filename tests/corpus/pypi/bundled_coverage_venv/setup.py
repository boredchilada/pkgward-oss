from setuptools import setup, find_packages

setup(
    name="portman-proxy",
    version="0.1.2",
    description="Local reverse proxy for production-like .localhost domains",
    packages=find_packages(),
    install_requires=["aiohttp", "typer", "rich"],
)
