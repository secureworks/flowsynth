from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="flowsynth",
    version="1.3.0",
    author="Will Urbanski",
    maintainer="David Wharton",
    maintainer_email="counterthreatunit@users.noreply.github.com",
    description="Flowsynth is a tool for rapidly modeling network traffic. Flowsynth can be used to generate text-based hexdumps of packets as well as native libpcap format packet captures.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/secureworks/flowsynth",
    package_dir={"flowsynth": "src"},
    packages=["flowsynth"],
    install_requires=[
        "scapy>=2.4.0",
        "argparse",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
    ],
    python_requires='>=2.7',
    keywords='pcap, pcaps, packet capture, libpcap, IDS, IPS, packets, scapy',
    project_urls={
        'Documentation': 'https://github.com/secureworks/flowsynth/blob/master/README.md',
        'Source': 'https://github.com/secureworks/flowsynth',
    },
)
