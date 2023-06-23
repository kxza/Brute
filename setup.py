#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
	name='brute',
	version='0.0.1',
	packages=['src','src.modules'],
	entry_points={
		"console_scripts": ["brute=src.main:main"]
	}
)
