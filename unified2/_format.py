pkt_header = ('>II', ['type', 'length'])
pkt_types = {2: [('>IIIIIII4s',
      ['sensor_id',
       'event_id',
       'event_second',
       'packet_second',
       'packet_microsecond',
       'linktype',
       'packet_length',
       'packet_data'])],
 7: [('>IIIIIIIIIIIHHBBBBIHH',
      ['sensor_id',
       'event_id',
       'event_second',
       'event_microsecond',
       'signature_id',
       'generator_id',
       'signature_revision',
       'classification_id',
       'priority_id',
       'ip_source',
       'ip_destination',
       'sport_itype',
       'dport_icode',
       'protocol',
       'impact_flag',
       'impact',
       'blocked',
       'mpls_label',
       'vlanId',
       'pad2']),
     ('>IIIIIIIIIIIHHBBBB',
      ['sensor_id',
       'event_id',
       'event_second',
       'event_microsecond',
       'signature_id',
       'generator_id',
       'signature_revision',
       'classification_id',
       'priority_id',
       'ip_source',
       'ip_destination',
       'sport_itype',
       'dport_icode',
       'protocol',
       'impact_flag',
       'impact',
       'blocked'])],
 72: [('>IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIHHBBBBIHH',
       ['sensor_id',
        'event_id',
        'event_second',
        'event_microsecond',
        'signature_id',
        'generator_id',
        'signature_revision',
        'classification_id',
        'priority_id',
        'ip_source',
        'ip_source',
        'ip_source',
        'ip_source',
        'ip_destination',
        'ip_destination',
        'ip_destination',
        'ip_destination',
        'sport_itype',
        'dport_icode',
        'protocol',
        'impact_flag',
        'impact',
        'blocked',
        'mpls_label',
        'vlanId',
        'pad2']),
      ('>IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIHHBBBB',
       ['sensor_id',
        'event_id',
        'event_second',
        'event_microsecond',
        'signature_id',
        'generator_id',
        'signature_revision',
        'classification_id',
        'priority_id',
        'ip_source',
        'ip_source',
        'ip_source',
        'ip_source',
        'ip_destination',
        'ip_destination',
        'ip_destination',
        'ip_destination',
        'sport_itype',
        'dport_icode',
        'protocol',
        'impact_flag',
        'impact',
        'blocked'])],
 104: [('>IIIIIIIIIIIHHBBBBIHH',
        ['sensor_id',
         'event_id',
         'event_second',
         'event_microsecond',
         'signature_id',
         'generator_id',
         'signature_revision',
         'classification_id',
         'priority_id',
         'ip_source',
         'ip_destination',
         'sport_itype',
         'dport_icode',
         'protocol',
         'impact_flag',
         'impact',
         'blocked',
         'mpls_label',
         'vlanId',
         'pad2'])],
 105: [('>IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIHHBBBBIHH',
        ['sensor_id',
         'event_id',
         'event_second',
         'event_microsecond',
         'signature_id',
         'generator_id',
         'signature_revision',
         'classification_id',
         'priority_id',
         'ip_source',
         'ip_source',
         'ip_source',
         'ip_source',
         'ip_destination',
         'ip_destination',
         'ip_destination',
         'ip_destination',
         'sport_itype',
         'dport_icode',
         'protocol',
         'impact_flag',
         'impact',
         'blocked',
         'mpls_label',
         'vlanId',
         'pad2'])],
 110: [('>II', ['event_type', 'event_length'])],
 207: [('>IIIIIIIIIIIHHBBBBIHH16sIIIII16s16s16s16s16s',
        ['sensor_id',
         'event_id',
         'event_second',
         'event_microsecond',
         'signature_id',
         'generator_id',
         'signature_revision',
         'classification_id',
         'priority_id',
         'ip_source',
         'ip_destination',
         'sport_itype',
         'dport_icode',
         'protocol',
         'impact_flag',
         'impact',
         'blocked',
         'mpls_label',
         'vlanId',
         'pad',
         'policy_uuid',
         'user_id',
         'web_application_id',
         'client_application_id',
         'application_protocol_id',
         'policyengine_rule_id',
         'policyengine_policy_uuid',
         'interface_ingress_uuid',
         'interface_egress_uuid',
         'security_zone_ingress_uuid',
         'security_zone_egress_uuid'])],
 208: [('>IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIHHBBBBIHH16sIIIII16s16s16s16s16s',
        ['sensor_id',
         'event_id',
         'event_second',
         'event_microsecond',
         'signature_id',
         'generator_id',
         'signature_revision',
         'classification_id',
         'priority_id',
         'ip_source',
         'ip_source',
         'ip_source',
         'ip_source',
         'ip_destination',
         'ip_destination',
         'ip_destination',
         'ip_destination',
         'sport_itype',
         'dport_icode',
         'protocol',
         'impact_flag',
         'impact',
         'blocked',
         'mpls_label',
         'vlanId',
         'pad',
         'policy_uuid',
         'user_id',
         'web_application_id',
         'client_application_id',
         'application_protocol_id',
         'policyengine_rule_id',
         'policyengine_policy_uuid',
         'interface_ingress_uuid',
         'interface_egress_uuid',
         'security_zone_ingress_uuid',
         'security_zone_egress_uuid'])]}
pkt_tails = {110: [('>IIIIII',
        ['sensor_id',
         'event_id',
         'event_second',
         'type',
         'data_type',
         'blob_length'])]}


if __name__ == '__main__':
	# Usage:
	#  bzr branch lp:pyclibrary
	#  cd pyclibrary
	#  python .../_snort_u2_format.py .../snort-2.9.2.1/src/sfutil/Unified2_common.h

	import sys, struct, CParser

	parser = CParser.CParser(sys.argv[1:])
	parser.processAll()

	structs = dict(
		(name, parser.defs['structs'][k]) for name, (ctype, k) in (
			(name, ( typedef if isinstance(typedef, tuple)
				else tuple(typedef[0].split(None, 1)) ))
			for name, typedef in parser.defs['types'].viewitems()
			if 'Unified2' in name )
		if ctype == 'struct' and ' ' not in name )

	def struct_spec( name,
			_ctypes={ 'uint32_t': 'I', 'uint16_t': 'H',
				'uint8_t': 'B', 'struct in6_addr': 'IIII' } ):
		typedef, names = '', list()
		for name, ctype, unused in structs[name]['members']:
			if len(ctype) == 2: ctype, cnt = ctype[0], ctype[1][0]
			elif len(ctype) == 1: ctype, cnt = ctype[0], 1
			else: raise ValueError(ctype)
			try:
				spec_atom = _ctypes[ctype]
				spec, cnt = spec_atom * cnt, len(spec_atom) * cnt
			except KeyError: print 'K', ctype
			if cnt > 1 and spec_atom == 'B':
				spec, cnt = '{}s'.format(cnt), 1
			for i in xrange(cnt):
				typedef += spec
				names.append(name)
		return '>' + typedef, names

	types = dict( (k,v)
		for k,v in parser.defs['values'].viewitems()
		if k.startswith('UNIFIED2_') )
	pkt_types = dict(
		( types[k], [struct_spec(v)]
			if isinstance(v, bytes) else map(struct_spec, v) )
		for k,v in dict(
			UNIFIED2_IDS_EVENT=[
				'Unified2IDSEvent', 'Serial_Unified2IDSEvent_legacy' ],
			UNIFIED2_IDS_EVENT_IPV6=[
				'Unified2IDSEventIPv6', 'Serial_Unified2IDSEventIPv6_legacy' ],
			UNIFIED2_IDS_EVENT_NG='Unified2IDSEventNG',
			UNIFIED2_IDS_EVENT_IPV6_NG='Unified2IDSEventIPv6_NG',
			UNIFIED2_PACKET='Serial_Unified2Packet',
			UNIFIED2_EXTRA_DATA='Unified2ExtraDataHdr',
			UNIFIED2_IDS_EVENT_VLAN='Unified2IDSEvent',
			UNIFIED2_IDS_EVENT_IPV6_VLAN='Unified2IDSEventIPv6' ).viewitems() )
	pkt_tails = dict(
		( types[k], [struct_spec(v)]
			if isinstance(v, bytes) else map(struct_spec, v) )
		for k,v in dict(
			UNIFIED2_EXTRA_DATA='SerialUnified2ExtraData' ).viewitems() )
	pkt_header = struct_spec('Serial_Unified2_Header')

	from pprint import pformat
	print 'pkt_header = {}'.format(pformat(pkt_header))
	print 'pkt_types = {}'.format(pformat(pkt_types))
	print 'pkt_tails = {}'.format(pformat(pkt_tails))
