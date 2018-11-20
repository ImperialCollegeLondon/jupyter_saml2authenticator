#!/usr/bin/env python
# coding: utf-8

# Copyright (c) Juptyer Development Team.
# Distributed under the terms of the Modified BSD License.

#-----------------------------------------------------------------------------
# Minimal Python version sanity check (from IPython/Jupyterhub)
#-----------------------------------------------------------------------------
from __future__ import print_function

import os
import sys

v = sys.version_info
if v[:2] < (3,3):
    error = "ERROR: Jupyter Hub requires Python version 3.3 or above."
    print(error, file=sys.stderr)
    sys.exit(1)


if os.name in ('nt', 'dos'):
    error = "ERROR: Windows is not supported"
    print(error, file=sys.stderr)

# At least we're on the python version we need, move on.

from distutils.core import setup

pjoin = os.path.join
here = os.path.abspath(os.path.dirname(__file__))

# Get the current package version.
version_ns = {}
with open(pjoin(here, 'jupyter_saml2authenticator', '_version.py')) as f:
    exec(f.read(), {}, version_ns)


setup_args = dict(
    name                = 'jupyter_saml2authenticator',
    packages            = ['jupyter_saml2authenticator'],
    version             = version_ns['__version__'],
    description         = "Saml2Authenticator: Authenticate JupyterHub users with SAML2 IdP providers",
    long_description    = open("README.md").read(),
    long_description_content_type = "text/markdown",
    author              = "Simon Clifford",
    author_email        = "Simon Clifford <SimonClifford@users.noreply.github.com>",
    url                 = "https://github.com/ImperialCollegeLondon/jupyter_saml2authenticator",
    license             = "Apache 2.0",
    platforms           = "Linux, Mac OS X",
    keywords            = ['JupyterHub', 'Jupyter', 'SAML2', 'Single-sign-on',
                           'Authenticator', ],
    classifiers         = [
        'Framework :: Jupyter',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
)

if 'bdist_wheel' in sys.argv:
    import setuptools

# setuptools requirements
if 'setuptools' in sys.modules:
    setup_args['install_requires'] = install_requires = []
    with open('requirements.txt') as f:
        for line in f.readlines():
            req = line.strip()
            if not req or req.startswith(('-e', '#')):
                continue
            install_requires.append(req)


def main():
    setup(**setup_args)

if __name__ == '__main__':
    main()
