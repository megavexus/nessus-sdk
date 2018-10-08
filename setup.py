#!/usr/bin/python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
try:  # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError:  # for pip <= 9.0.3
    from pip.req import parse_requirements
from glob import glob

REQUIREMENTS = [str(ir.req) for ir in parse_requirements(
    'requirements.txt',  session=False)]
REQUIREMENTS_TEST = [str(ir.req) for ir in parse_requirements(
    'requirements-test.txt',  session=False)]

setup(
    name='nessus-sdk',
    version='0.1_i2',
    description='SDK de Nessus para la DISMA de MAPFRE',

    author='Javier Gutiérrez',
    author_email='gnjavie@3p.mapfre.es',

    url='https://10.229.214.133/revisiones/nessus-sdk',

    install_requires=REQUIREMENTS,

    packages=find_packages(where='src'),
    include_package_data=True,
    package_dir={'': 'src'},
    zip_safe=False,
    data_files=[('requs', glob('*.txt'))],

    # Testing
    setup_requires=["pytest-runner"],
    tests_require=REQUIREMENTS_TEST,
)
