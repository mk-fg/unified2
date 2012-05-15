#!/usr/bin/env python

import os, sys

from setuptools import setup, find_packages

pkg_root = os.path.dirname(__file__)

setup(

	name = 'unified2',
	version = '12.05.1',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'unified2 u2 ids snort suricata parser',
	url = 'http://github.com/mk-fg/unified2',

	description = 'unified2 IDS binary log format parser',
	long_description = open(os.path.join(pkg_root, 'README.md')).read(),

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

	packages = find_packages() )
