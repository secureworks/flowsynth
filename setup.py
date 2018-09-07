#!/usr/bin/env python

from setuptools import setup, find_packages

install_requires = [
    'scapy>=2.4.0',
    'argparse',
]

print find_packages()

if __name__ == '__main__':
    setup(
        name='flowsynth',
        version='0.1',
        description='Tool for rapidly modelling network traffic.',
        author='Will Urbanski',
        author_email='will.urbanski@gmail.com',
        install_requires=install_requires,
        license='Apache License 2.0',
        url='https://github.com/secureworks/flowsynth',
        packages=find_packages(),
        scripts=[
            'flowsynth/flowsynth.py',
        ],
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Environment :: Console',
            'Intended Audience :: Developers',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 3',
            'Topic :: Software Development :: Libraries',
            'Topic :: System :: Networking'
        ],
        zip_safe=False,
    )
