from setuptools import setup

setup(
    name="quantum-core-engine",
    version="3.0.0",
    packages=["quantum", "quantum.pytransform"],
    package_data={
        "quantum": [
            "_pytransform.so",
            "_pytransform.dll",
            "_pytransform.dylib",
            "pytransform/*",
        ],
    },
    install_requires=[
        "boto3>=1.26",
        "cryptography>=41.0",
        "requests>=2.31",
        "psutil>=5.9",
        "GPUtil>=1.4",
    ],
)
