from setuptools import setup

setup(
    name="flowsynth",
    version=0.1,
    description="IDS Utility Library",
    url="https://github.com/secureworks/flowsynth",
    license="Apache",
    scripts = [
        "src/flowsynth"
    ],
    install_requires=['scapy','argparse']
)