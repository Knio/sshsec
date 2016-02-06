from setuptools import setup

import imp
_version = imp.load_source("sshsec._version", "sshsec/_version.py")

setup(
    name='sshsec',
    version=_version.__version__,
    author='Tom Flanagan',
    author_email='tom@zkpq.ca',
    license='MIT',
    url='https://github.com/Knio/sshsec',

    description='SSH server configuration tester',
    packages=['sshsec'],
    keywords='ssh server configuration security networking',

    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities',
    ]
)
