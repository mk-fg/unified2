#!/usr/bin/env python

import os, sys

from setuptools import setup, find_packages

# Error-handling here is to allow package to be built w/o README included
try:
	readme = open(os.path.join(
		os.path.dirname(__file__), 'README.txt' )).read()
except IOError: readme = ''

setup(

	name = 'unified2',
	version = '12.07.0',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'unified2 u2 ids snort suricata parser',
	url = 'http://github.com/mk-fg/unified2',

	description = 'unified2 IDS binary log format parser',
	long_description = readme,

	classifiers = [
		'Development Status :: 4 - Beta',
		'Intended Audience :: Developers',
		'Intended Audience :: System Administrators',
		'Intended Audience :: Telecommunications Industry',
		'License :: OSI Approved',
		'Operating System :: POSIX',
		'Operating System :: Unix',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Security',
		'Topic :: System :: Networking :: Monitoring' ],

	packages = find_packages(),
	package_data = {'': ['README.txt']},
	exclude_package_data = {'': ['README.*']} )
