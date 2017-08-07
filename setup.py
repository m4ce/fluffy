import os
from setuptools import setup, find_packages
from fluffy import __version__ as version

with open(os.path.join(os.getcwd(), 'README.md')) as f:
    readme = f.read()

setup(
    name='pyfluffy',
    version=version,
    description='Fluffy - A Firewall as a Service',
    long_description=readme,
    author='Matteo Cerutti',
    author_email='matteo.cerutti@hotmail.co.uk',
    url='https://github.com/m4ce/fluffy',
    license='Apache License 2.0',
    packages=find_packages(exclude=['tests', 'etc', 'examples']),
    include_package_data=True,
    keywords=[
        'firewall',
        'fwaas',
        'firewall as a service',
        'iptables as a service'
    ],
    install_requires=[
        'flasgger',
        'Flask',
        'Flask-API',
        'subprocess32',
        'futures',
        'pyroute2',
        'python-unshare'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Framework :: Flask',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: System :: Networking :: Firewalls'
    ],
    entry_points={
        'console_scripts': [
            'fluffyd = fluffy.dev:main'
        ]
    }
)
