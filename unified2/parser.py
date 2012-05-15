# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import struct

from unified2._format import pkt_header, pkt_types, pkt_tails


class Parser(object):

	def __init__(self):
		self.data_fmts = dict(header=self.struct(pkt_header))
		self.data_fmts.update((k, map(self.struct, v)) for k,v in pkt_types.viewitems())
		self.data_tails = dict((k, map(self.struct, v)) for k,v in pkt_tails.viewitems())
		self.read_fmt = 'header'
		self.read_pos, self.read_len = 0, self.data_fmts[self.read_fmt][0]

	def struct(self, spec):
		fmt, keys = spec
		return struct.calcsize(fmt), fmt, keys

	def unpack(self, type_id, buff, type_tail=False):
		# Snort type_id=7,72 can match different structs of different length,
		#  hence the check by-length - longest fitting struct is chosen.
		# How anyone could ever think that it's a good idea? *sigh*
		pkt_fmt, pkt_len = ( self.data_fmts
			if not type_tail else self.data_tails )[type_id], len(buff)
		if isinstance(pkt_fmt, list):
			for fmt_len, fmt, keys in pkt_fmt:
				if fmt_len <= pkt_len: break
			else:
				raise ValueError('Packet length in header is'
					' lesser than size of all known structs for this type')
		else: fmt_len, fmt, keys = pkt_fmt

		pkt, tail = dict(), buff[fmt_len:]
		for k,v in it.izip(keys, struct.unpack_from(fmt, buff)):
			if k not in pkt: pkt[k] = v
			elif isinstance(pkt[k], list): pkt[k].append(v)
			else: pkt[k] = [pkt[k], v]

		if not type_tail and type_id in self.data_tails:
			tail = self.unpack(type_id, tail, type_tail=True)
		return pkt, tail

	def read(self, src):
		buff = src.read(self.read_len)
		self.read_pos += len(buff)
		return buff

	def process(self, buff):
		if self.read_pos < self.read_len: return buff, None
		buff, buff_tail = buff[:self.read_len], buff[self.read_len:]
		pkt, pkt_tail = self.unpack(self.read_fmt, buff)
		if self.read_fmt == 'header':
			self.read_len, self.read_fmt = pkt['length'], pkt['type']
			pkt = None
		else:
			self.read_fmt = 'header'
			self.read_len = self.data_fmts[self.read_fmt][0]
			pkt = pkt, pkt_tail
		self.read_pos = len(buff_tail)
		return buff_tail, pkt


def read(src):
	'Event generator from u2 stream.'
	parser, buff_agg = Parser(), ''
	while True:
		buff = parser.read(src)
		if not buff: break # EOF
		buff_agg += buff
		while True:
			buff_agg, ev = parser.process(buff_agg)
			if ev is None: break
			yield ev

def parse(path):
	'Event generator from path to u2 file.'
	return read(open(path, 'rb'))


if __name__ == '__main__':
	import sys
	for ev, ev_tail in parse(sys.argv[1]):
		print('Event:', ev)
		if ev_tail: print('Event tail:', ev_tail)
