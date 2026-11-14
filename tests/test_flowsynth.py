"""tests for flowsynth's generated MACs, sequence numbers, ports and seeding

run with: python -m unittest discover tests  (or: python -m pytest tests)
"""
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import datetime
import tempfile
import unittest

SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src')
sys.path.insert(0, SRC_DIR)

import flowsynth  # noqa: E402
from scapy.all import Ether, IP, IPv6, TCP, UDP, rdpcap  # noqa: E402

CLIENT = '10.0.0.5'
SERVER = '192.168.1.10'
DNS = '8.8.8.8'

SYNTH = """
flow web tcp 10.0.0.5:44123 > 192.168.1.10:80 (tcp.initialize;);
web > (content:"GET / HTTP/1.1\\x0d\\x0aHost: example\\x0d\\x0a\\x0d\\x0a";);
web < (content:"HTTP/1.1 200 OK\\x0d\\x0aContent-Length: 2\\x0d\\x0a\\x0d\\x0ahi";);
web > (tcp.flags.ack; tcp.noack;);
flow dns udp 10.0.0.5:53000 > 8.8.8.8:53;
dns > (content:"\\x12\\x34\\x01\\x00";);
dns < (content:"\\x12\\x34\\x81\\x80";);
"""


class FlowsynthTestCase(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def build(self, synth=SYNTH, seed=None, name='out', start_time=None):
        """build a synth via the Model API; return the pcap path"""
        synth_path = os.path.join(self.tmpdir, name + '.synth')
        pcap_path = os.path.join(self.tmpdir, name + '.pcap')
        with open(synth_path, 'w') as fptr:
            fptr.write(synth)
        flowsynth.Model(input=synth_path, output_format='pcap', output_file=pcap_path,
                        quiet=True, seed=seed, start_time=start_time).build()
        return pcap_path

    def read_bytes(self, path):
        with open(path, 'rb') as fptr:
            return fptr.read()


class TestMacs(FlowsynthTestCase):

    def test_one_mac_per_host(self):
        macs = {}
        for pkt in rdpcap(self.build()):
            macs.setdefault(pkt[IP].src, set()).add(pkt[Ether].src)
            macs.setdefault(pkt[IP].dst, set()).add(pkt[Ether].dst)
        self.assertEqual(sorted(macs), sorted([CLIENT, SERVER, DNS]))
        for host, host_macs in macs.items():
            self.assertEqual(len(host_macs), 1, "%s has MACs %s" % (host, host_macs))
        # and different hosts get different MACs
        self.assertEqual(len(set(m for s in macs.values() for m in s)), 3)

    def test_default_macs_unicast_locally_administered(self):
        for _ in range(20):
            for pkt in rdpcap(self.build()):
                for mac in (pkt[Ether].src, pkt[Ether].dst):
                    first_octet = int(mac.split(':')[0], 16)
                    self.assertEqual(first_octet & 0x01, 0, "group bit set in %s" % mac)
                    self.assertEqual(first_octet & 0x02, 0x02, "not locally administered: %s" % mac)

    def test_explicit_macs_are_used(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 '
                 '(src_mac: 00:11:22:33:44:55; dst_mac: 00:aa:bb:cc:dd:ee;);\n'
                 'f > (content:"x";);\n')
        pkts = rdpcap(self.build(synth))
        self.assertEqual((pkts[0][Ether].src, pkts[0][Ether].dst), ('00:11:22:33:44:55', '00:aa:bb:cc:dd:ee'))
        self.assertEqual((pkts[1][Ether].src, pkts[1][Ether].dst), ('00:aa:bb:cc:dd:ee', '00:11:22:33:44:55'))

    def test_explicit_mac_becomes_host_default(self):
        synth = ('flow a tcp 10.0.0.1:1234 > 10.0.0.2:80 (src_mac: 00:11:22:33:44:55;);\n'
                 'a > (content:"x";);\n'
                 'flow b udp 10.0.0.1:5353 > 10.0.0.3:53;\n'
                 'b > (content:"y";);\n')
        macs = set()
        for pkt in rdpcap(self.build(synth)):
            for addr, mac in ((pkt[IP].src, pkt[Ether].src), (pkt[IP].dst, pkt[Ether].dst)):
                if addr == '10.0.0.1':
                    macs.add(mac)
        self.assertEqual(macs, {'00:11:22:33:44:55'})

    def test_explicit_mac_is_the_hosts_mac_in_every_flow(self):
        synth = ('flow a udp 10.0.0.1:1 > 10.0.0.2:2;\n'
                 'a > (content:"x";);\n'
                 'flow b udp 10.0.0.1:3 > 10.0.0.3:4 (src_mac: 00:11:22:33:44:55;);\n'
                 'b > (content:"y";);\n'
                 'flow c udp 10.0.0.3:5 > 10.0.0.1:6;\n'
                 'c > (content:"z";);\n')
        pkts = rdpcap(self.build(synth))
        # flow a comes before the flow that sets the MAC, and still uses it
        self.assertEqual([pkts[0][Ether].src, pkts[1][Ether].src, pkts[2][Ether].dst], ['00:11:22:33:44:55'] * 3)

    def test_ipv6_host_written_two_ways(self):
        synth = ('flow a udp [2001:db8::1]:1 > [2001:db8::2]:2;\n'
                 'a > (content:"x";);\n'
                 'flow b udp [2001:0db8:0::1]:3 > [2001:db8::3]:4;\n'
                 'b > (content:"y";);\n')
        pkts = rdpcap(self.build(synth))
        self.assertEqual(pkts[0][Ether].src, pkts[1][Ether].src)

    def test_invalid_mac_rejected(self):
        flowdecl = {'name': 'f', 'l3_proto': flowsynth.Flow.PROTO_IPV4, 'l4_proto': flowsynth.Flow.PROTO_TCP,
                    'src_host': '10.0.0.1', 'src_port': '1', 'dst_host': '10.0.0.2', 'dst_port': '2',
                    'flow': '>', 'attributes': {'src_mac': '00:11:22:33:44:556'}}
        self.assertRaises(flowsynth.SynSyntaxError, flowsynth.Flow, flowdecl)


class TestTcpSequence(FlowsynthTestCase):

    def tcp_packets(self, path):
        return [pkt[TCP] for pkt in rdpcap(path) if TCP in pkt]

    def test_isns_are_random_32bit(self):
        isns = set()
        for i in range(5):
            syn, synack = self.tcp_packets(self.build(name='b%d' % i))[:2]
            self.assertEqual(str(syn.flags), 'S')
            self.assertEqual(str(synack.flags), 'SA')
            isns.update([syn.seq, synack.seq])
        self.assertNotIn(10, isns)
        self.assertNotIn(100, isns)
        self.assertGreater(len(isns), 1)
        # values spread over the full 32-bit space, not the old 10000-99999 range
        self.assertTrue(any(isn > 99999 for isn in isns))

    def assert_seq_ack_consistent(self, tcp_pkts):
        """check every packet against the expected next seq of each side"""
        syn, synack = tcp_pkts[:2]
        self.assertEqual((str(syn.flags), syn.ack), ('S', 0))
        self.assertEqual(str(synack.flags), 'SA')
        self.assertEqual(synack.ack, (syn.seq + 1) % 2**32)
        next_seq = {syn.sport: (syn.seq + 1) % 2**32, syn.dport: (synack.seq + 1) % 2**32}
        for pkt in tcp_pkts[2:]:
            flags = str(pkt.flags)
            self.assertEqual(pkt.seq, next_seq[pkt.sport], "bad seq: %r" % pkt)
            if 'A' in flags:
                self.assertEqual(pkt.ack, next_seq[pkt.dport], "bad ack: %r" % pkt)
            # SYN and FIN each consume one sequence number
            consumed = len(pkt.payload) + (1 if ('S' in flags or 'F' in flags) else 0)
            next_seq[pkt.sport] = (pkt.seq + consumed) % 2**32

    def test_seq_ack_consistent(self):
        tcp_pkts = self.tcp_packets(self.build())
        # handshake, request + ACK, response + ACK, bare ACK
        self.assertEqual(len(tcp_pkts), 8)
        self.assert_seq_ack_consistent(tcp_pkts)

    def test_no_ack_for_bare_packets(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (tcp.initialize;);\n'
                 'f > (content:"x";);\n'
                 'f > (tcp.flags.ack;);\n'
                 'f < (tcp.flags.ack;);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))
        # handshake, data + ACK, then the two bare ACKs with no reply
        self.assertEqual([str(p.flags) for p in tcp_pkts], ['S', 'SA', 'A', 'PA', 'A', 'A', 'A'])
        self.assertEqual([p.sport for p in tcp_pkts[-2:]], [1234, 80])
        self.assert_seq_ack_consistent(tcp_pkts)

    CLOSE_SYNTH = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (tcp.initialize;);\n'
                   'f > (content:"hello";);\n'
                   'f < (content:"world!";);\n')

    def test_close_client_first(self):
        tcp_pkts = self.tcp_packets(self.build(self.CLOSE_SYNTH + 'f > (tcp.flags.fin;);\nf < (tcp.flags.fin;);\n'))
        flags = [(p.sport, str(p.flags)) for p in tcp_pkts[-4:]]
        self.assertEqual(flags, [(1234, 'FA'), (80, 'A'), (80, 'FA'), (1234, 'A')])
        fin, fin_ack, peer_fin, last_ack = tcp_pkts[-4:]
        self.assertEqual(fin_ack.ack, fin.seq + 1)
        self.assertEqual(peer_fin.ack, fin.seq + 1)
        self.assertEqual((last_ack.seq, last_ack.ack), (fin.seq + 1, peer_fin.seq + 1))
        self.assert_seq_ack_consistent(tcp_pkts)

    def test_close_server_first(self):
        tcp_pkts = self.tcp_packets(self.build(self.CLOSE_SYNTH + 'f < (tcp.flags.fin;);\nf > (tcp.flags.fin;);\n'))
        flags = [(p.sport, str(p.flags)) for p in tcp_pkts[-4:]]
        self.assertEqual(flags, [(80, 'FA'), (1234, 'A'), (1234, 'FA'), (80, 'A')])
        fin, fin_ack, peer_fin, last_ack = tcp_pkts[-4:]
        self.assertEqual(fin_ack.ack, fin.seq + 1)
        self.assertEqual(peer_fin.ack, fin.seq + 1)
        self.assertEqual((last_ack.seq, last_ack.ack), (fin.seq + 1, peer_fin.seq + 1))
        self.assert_seq_ack_consistent(tcp_pkts)

    def test_close_combined_fin_ack(self):
        # tcp.noack on the first FIN lets the peer's FIN carry the ACK
        tcp_pkts = self.tcp_packets(self.build(self.CLOSE_SYNTH +
                                               'f > (tcp.flags.fin; tcp.noack;);\nf < (tcp.flags.fin;);\n'))
        self.assertEqual([(p.sport, str(p.flags)) for p in tcp_pkts[-3:]],
                         [(1234, 'FA'), (80, 'FA'), (1234, 'A')])
        self.assert_seq_ack_consistent(tcp_pkts)

    def test_fin_with_payload(self):
        tcp_pkts = self.tcp_packets(self.build(self.CLOSE_SYNTH + 'f < (content:"bye"; tcp.flags.fin;);\n'))
        fin, fin_ack = tcp_pkts[-2:]
        self.assertEqual((str(fin.flags), bytes(fin.payload)), ('FPA', b'bye'))
        self.assertEqual(fin_ack.ack, fin.seq + 3 + 1)
        self.assert_seq_ack_consistent(tcp_pkts)

    def test_manual_handshake(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80;\n'
                 'f > (tcp.flags.syn;);\n'
                 'f < (tcp.flags.synack;);\n'
                 'f > (tcp.flags.ack;);\n'
                 'f > (content:"x";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))
        self.assertEqual([str(p.flags) for p in tcp_pkts], ['S', 'SA', 'A', 'PA', 'A'])
        self.assert_seq_ack_consistent(tcp_pkts)

    # a hand-written handshake with known ISNs: the client's data starts at 1000
    HANDSHAKE = ('f > (tcp.flags.syn; tcp.seq: 999; tcp.noack;);\n'
                 'f < (tcp.flags.synack; tcp.seq: 4999; tcp.noack;);\n'
                 'f > (tcp.flags.ack; tcp.noack;);\n')

    def flow(self, mss=None):
        attrs = ' (mss: %d;)' % mss if mss else ''
        return 'flow f tcp 10.0.0.1:1234 > 10.0.0.2:80%s;\n' % attrs + self.HANDSHAKE

    def test_manual_seq_starts_the_stream(self):
        # with no handshake, a manual seq on a side's first packet sets its stream
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80;\n'
                 'f > (content:"abc"; tcp.seq: 1000;);\n'
                 'f > (content:"de";);\n')
        data, data_ack, follow, follow_ack = self.tcp_packets(self.build(synth))
        self.assertEqual((data.seq, data_ack.ack, follow.seq, follow_ack.ack), (1000, 1003, 1003, 1005))

    def test_manual_seq_ahead_leaves_a_hole(self):
        # data past a hole moves the sender on, but the receiver keeps ACKing the hole
        synth = self.flow() + ('f > (content:"abc"; tcp.seq: 2000;);\n'
                               'f > (content:"de";);\n'
                               'f < (content:"ok";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))
        manual, manual_ack, follow, follow_ack, resp, resp_ack = tcp_pkts[3:]
        self.assertEqual((manual.seq, manual_ack.ack), (2000, 1000))
        self.assertEqual((follow.seq, follow_ack.ack), (2003, 1000))
        self.assertEqual((resp.seq, resp.ack), (5000, 1000))
        self.assertEqual((resp_ack.seq, resp_ack.ack), (2005, 5002))

    def test_readme_seq_example(self):
        synth = ('flow default tcp 10.0.0.1:1234 > 10.0.0.2:80;\n'
                 'default > (content:"abc"; tcp.seq: 1000;);\n'
                 'default > (content:"de";);\n'
                 'default > (content:"AB"; tcp.seq: 1000;);\n'
                 'default > (content:"jk"; tcp.seq: 1009;);\n'
                 'default > (content:"fghi"; tcp.seq: 1005;);\n'
                 'default > (content:"x";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))
        self.assertEqual([p.seq for p in tcp_pkts[0::2]], [1000, 1003, 1000, 1009, 1005, 1011])
        self.assertEqual([p.ack for p in tcp_pkts[1::2]], [1003, 1005, 1005, 1005, 1011, 1012])

    def test_inferred_ack_starts_the_peers_stream(self):
        # the client's automatic ACK of the banner is its first packet, so a later
        # tcp.seq from the client is checked against its stream, not taken as a start
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:25 (tcp.client_isn: 1000; tcp.server_isn: 5000;);\n'
                 'f < (content:"220 hi";);\n'
                 'f > (content:"EHLO"; tcp.seq: 900;);\n'
                 'f > (content:"x";);\n')
        banner, banner_ack, ehlo, ehlo_ack, nxt, _ = self.tcp_packets(self.build(synth))
        self.assertEqual(banner_ack.seq, 1000)
        self.assertEqual((ehlo.seq, ehlo_ack.ack, nxt.seq), (900, 1000, 1000))

    def test_hole_filled_across_the_wrap(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (tcp.client_isn: 4294967290; tcp.server_isn: 1;);\n'
                 'f > (content:"abcd";);\n'
                 'f > (content:"ij"; tcp.seq: 2;);\n'
                 'f > (content:"efgh"; tcp.seq: 4294967294;);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))
        self.assertEqual([p.seq for p in tcp_pkts[0::2]], [4294967290, 2, 4294967294])
        self.assertEqual([p.ack for p in tcp_pkts[1::2]], [4294967294, 4294967294, 4])

    def test_bare_packet_ahead_does_not_move_the_stream(self):
        synth = self.flow() + ('f > (content:"abc";);\n'
                               'f > (tcp.flags.ack; tcp.seq: 2000;);\n'
                               'f > (content:"de";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))[3:]
        self.assertEqual([p.seq for p in tcp_pkts], [1000, 5000, 2000, 1003, 5000])
        self.assertEqual(tcp_pkts[-1].ack, 1005)

    def test_warns_about_server_seq_after_automatic_ack(self):
        # the server's automatic ACK is its first packet, so its tcp.seq is compared
        # with a random sequence number
        synth = ('flow f tcp 10.0.0.1:1 > 10.0.0.2:2;\n'
                 'f > (content:"GET"; tcp.seq: 1000;);\n'
                 'f < (content:"200"; tcp.seq: 5000;);\n')
        with self.assertLogs(level='WARNING') as logs:
            self.build(synth)
        self.assertIn('tcp.server_isn', logs.output[0])

    def test_no_warning_with_isn_attributes(self):
        synth = ('flow f tcp 10.0.0.1:1 > 10.0.0.2:2 (tcp.client_isn: 1000; tcp.server_isn: 5000;);\n'
                 'f > (content:"GET"; tcp.seq: 1000; tcp.ack: 5000;);\n'
                 'f < (content:"200"; tcp.seq: 5000;);\n'
                 'f < (content:"more";);\n')
        with self.assertNoLogs(level='WARNING'):
            tcp_pkts = self.tcp_packets(self.build(synth))
        self.assertEqual([p.seq for p in tcp_pkts[2::2]], [5000, 5003])
        self.assertEqual(tcp_pkts[-1].ack, 5007)

    def test_invalid_mss(self):
        for bad in ('0', '-1', 'abc', '65536'):
            flowdecl = {'name': 'f', 'l3_proto': flowsynth.Flow.PROTO_IPV4, 'l4_proto': flowsynth.Flow.PROTO_TCP,
                        'src_host': '10.0.0.1', 'src_port': '1', 'dst_host': '10.0.0.2', 'dst_port': '2',
                        'flow': '>', 'attributes': {'mss': bad}}
            self.assertRaises(flowsynth.SynSyntaxError, flowsynth.Flow, flowdecl)

    def test_fin_split_over_mss(self):
        synth = self.flow(mss=4) + 'f > (content:"abcdefghij"; tcp.flags.fin;);\n'
        tcp_pkts = self.tcp_packets(self.build(synth))[3:]
        self.assertEqual([str(p.flags) for p in tcp_pkts[0::2]], ['PA', 'PA', 'FPA'])
        self.assertEqual([p.ack for p in tcp_pkts[1::2]], [1004, 1008, 1011])

    def test_fin_with_manual_seq(self):
        synth = self.flow() + ('f > (content:"abc";);\n'
                               'f > (tcp.flags.fin; tcp.seq: 1003;);\n')
        fin, fin_ack = self.tcp_packets(self.build(synth))[-2:]
        self.assertEqual((str(fin.flags), fin.seq, fin_ack.ack), ('FA', 1003, 1004))

    def test_retransmission_leaves_the_flow(self):
        # resending earlier bytes must not rewind the stream or the peer's ACK
        synth = self.flow() + ('f > (content:"abc";);\n'
                               'f > (content:"def";);\n'
                               'f > (content:"ABC"; tcp.seq: 1000;);\n'
                               'f > (content:"ghi";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))[3:]
        data = [(p.seq, bytes(p.payload)) for p in tcp_pkts[0::2]]
        self.assertEqual(data, [(1000, b'abc'), (1003, b'def'), (1000, b'ABC'), (1006, b'ghi')])
        self.assertEqual([p.ack for p in tcp_pkts[1::2]], [1003, 1006, 1006, 1009])

    def test_overlap_past_the_stream_end(self):
        # a resent segment that runs past the end moves the stream to its end
        synth = self.flow(mss=4) + ('f > (content:"abcdefgh";);\n'
                                    'f > (content:"ABCDEFGHIJ"; tcp.seq: 1000;);\n'
                                    'f > (content:"x";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))[3:]
        self.assertEqual([p.seq for p in tcp_pkts[0::2]], [1000, 1004, 1000, 1004, 1008, 1010])
        self.assertEqual([p.ack for p in tcp_pkts[1::2]], [1004, 1008, 1008, 1008, 1010, 1011])

    def test_manual_seq_segmented(self):
        synth = 'flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (mss: 4;);\nf > (content:"abcdefghij"; tcp.seq: 5000;);\n'
        tcp_pkts = self.tcp_packets(self.build(synth))
        self.assertEqual([p.seq for p in tcp_pkts[0::2]], [5000, 5004, 5008])
        self.assertEqual([p.ack for p in tcp_pkts[1::2]], [5004, 5008, 5010])

    def test_manual_seq_ack_wrap(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80;\n'
                 'f > (content:"a"; tcp.seq: 4294967301; tcp.ack: 4294967297;);\n')
        data = self.tcp_packets(self.build(synth))[0]
        self.assertEqual((data.seq, data.ack), (5, 1))

    def test_isn_attributes_restore_old_numbers(self):
        # 1.4 synths that worked out absolute values from the old 10/100 ISNs
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (tcp.initialize; tcp.client_isn: 10; tcp.server_isn: 100;);\n'
                 'f > (content:"abc";);\n'
                 'f > (content:"abc"; tcp.seq: 11;);\n'
                 'f < (content:"ok";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))
        syn, synack = tcp_pkts[:2]
        self.assertEqual((syn.seq, synack.seq, synack.ack), (10, 100, 11))
        data, data_ack, resent, resent_ack, resp = tcp_pkts[3:8]
        self.assertEqual((data.seq, resent.seq), (11, 11))
        self.assertEqual((data_ack.ack, resent_ack.ack), (14, 14))
        self.assertEqual((resp.seq, resp.ack), (101, 14))

    def test_isn_attributes_midstream(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (tcp.client_isn: 4294967295; tcp.server_isn: 0;);\n'
                 'f > (content:"ab";);\n'
                 'f < (content:"c";);\n')
        data, data_ack, resp, resp_ack = self.tcp_packets(self.build(synth))
        self.assertEqual((data.seq, data_ack.ack), (4294967295, 1))
        self.assertEqual((resp.seq, resp.ack, resp_ack.ack), (0, 1, 1))

    def test_isn_attributes_keep_other_random_values(self):
        base = 'flow f tcp 10.0.0.1:any > 10.0.0.2:80 (tcp.initialize;%s);\nf > (content:"x";);\n'
        plain = rdpcap(self.build(base % '', seed=9, name='a'))
        fixed = rdpcap(self.build(base % ' tcp.client_isn: 10;', seed=9, name='b'))
        self.assertEqual(fixed[0][TCP].seq, 10)
        self.assertEqual(fixed[1][TCP].seq, plain[1][TCP].seq)      # server ISN unchanged
        self.assertEqual((fixed[0][TCP].sport, fixed[0][Ether].src), (plain[0][TCP].sport, plain[0][Ether].src))

    def test_warns_about_absolute_seq_with_random_isns(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (tcp.initialize;);\n'
                 'f > (content:"abc"; tcp.seq: 11;);\n'
                 'f > (content:"def"; tcp.seq: 14;);\n')
        with self.assertLogs(level='WARNING') as logs:
            self.build(synth)
        self.assertEqual(len(logs.output), 1)
        self.assertIn('tcp.client_isn', logs.output[0])

    def test_isn_attribute_invalid(self):
        for bad in ('-1', '4294967296', 'ten', '1.5'):
            flowdecl = {'name': 'f', 'l3_proto': flowsynth.Flow.PROTO_IPV4, 'l4_proto': flowsynth.Flow.PROTO_TCP,
                        'src_host': '10.0.0.1', 'src_port': '1', 'dst_host': '10.0.0.2', 'dst_port': '2',
                        'flow': '>', 'attributes': {'tcp.client_isn': bad}}
            self.assertRaises(flowsynth.SynSyntaxError, flowsynth.Flow, flowdecl)

    def test_rst_has_no_ack(self):
        synth = self.flow() + 'f < (tcp.flags.rst;);\n'
        tcp_pkts = self.tcp_packets(self.build(synth))
        self.assertEqual(len(tcp_pkts), 4)
        self.assertEqual((str(tcp_pkts[-1].flags), tcp_pkts[-1].seq, tcp_pkts[-1].ack), ('R', 5000, 0))

    def test_ipv6(self):
        synth = ('flow f tcp [2001:db8::1]:1234 > [2001:db8::2]:80 (tcp.initialize;);\n'
                 'f > (content:"abc";);\n'
                 'f < (content:"de";);\n')
        pkts = rdpcap(self.build(synth))
        self.assertTrue(all(IPv6 in p for p in pkts))
        self.assert_seq_ack_consistent([p[TCP] for p in pkts])

    def test_manual_ack_only_affects_its_packet(self):
        synth = ('flow f tcp 10.0.0.1:1234 > 10.0.0.2:80 (tcp.initialize;);\n'
                 'f > (content:"x"; tcp.ack: 7;);\n'
                 'f < (content:"y";);\n')
        tcp_pkts = self.tcp_packets(self.build(synth))
        synack = tcp_pkts[1]
        data, data_ack, resp = tcp_pkts[3:6]
        self.assertEqual(data.ack, 7)
        self.assertEqual(data_ack.seq, synack.seq + 1)
        self.assertEqual(resp.seq, synack.seq + 1)

    def test_seq_wraps_at_32_bits(self):
        real_getrandbits = flowsynth.RNG.getrandbits

        def near_wrap(k):
            if k == 32:
                return 2**32 - 5
            return real_getrandbits(k)

        flowsynth.RNG.getrandbits = near_wrap
        try:
            tcp_pkts = self.tcp_packets(self.build())
        finally:
            del flowsynth.RNG.getrandbits
        self.assertEqual(tcp_pkts[0].seq, 2**32 - 5)
        self.assertLess(tcp_pkts[-1].seq, 2**32 - 5)       # wrapped past zero
        self.assert_seq_ack_consistent(tcp_pkts)

    def test_seq_add(self):
        self.assertEqual(flowsynth.seq_add(1, 2), 3)
        self.assertEqual(flowsynth.seq_add(2**32 - 1, 1), 0)
        self.assertEqual(flowsynth.seq_add(2**32 - 2, 10), 8)


class TestPorts(FlowsynthTestCase):

    SYNTH_ANY = 'flow f udp 10.0.0.1:any > 10.0.0.2:53;\nf > (content:"x";);\nf < (content:"y";);\n'

    def test_any_port(self):
        pkts = rdpcap(self.build(self.SYNTH_ANY))
        sport = pkts[0][UDP].sport
        self.assertTrue(1024 <= sport <= 65000)
        # the same port for the life of the flow
        self.assertEqual(pkts[1][UDP].dport, sport)

    def test_any_port_tcp(self):
        synth = 'flow f tcp 10.0.0.1:any > 10.0.0.2:80 (tcp.initialize;);\nf > (content:"x";);\n'
        pkts = rdpcap(self.build(synth))
        sport = pkts[0][TCP].sport
        self.assertTrue(1024 <= sport <= 65000)
        self.assertEqual(set(p[TCP].sport for p in pkts if p[IP].src == '10.0.0.1'), {sport})
        self.assertEqual(set(p[TCP].dport for p in pkts if p[IP].src == '10.0.0.2'), {sport})

    def test_any_port_seeded(self):
        ports = set(rdpcap(self.build(self.SYNTH_ANY, seed=7, name=n))[0][UDP].sport for n in 'ab')
        self.assertEqual(len(ports), 1)


class TestSeed(FlowsynthTestCase):

    def test_same_seed_identical_bytes(self):
        first = self.read_bytes(self.build(seed=1234, name='a'))
        second = self.read_bytes(self.build(seed=1234, name='b'))
        self.assertEqual(first, second)

    def test_different_seed_differs(self):
        first = self.read_bytes(self.build(seed=1, name='a'))
        second = self.read_bytes(self.build(seed=2, name='b'))
        self.assertNotEqual(first, second)

    def test_no_seed_differs(self):
        seeded = self.read_bytes(self.build(seed=1, name='a'))
        first = self.read_bytes(self.build(name='b'))
        second = self.read_bytes(self.build(name='c'))
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, seeded)

    def test_seeded_timestamps(self):
        times = [float(pkt.time) for pkt in rdpcap(self.build(seed=1))]
        self.assertAlmostEqual(times[0], flowsynth.SEEDED_START_TIME)
        for prev, cur in zip(times, times[1:]):
            self.assertAlmostEqual(cur - prev, flowsynth.SEEDED_TIME_STEP, places=5)

    def test_cli_seed(self):
        synth_path = os.path.join(self.tmpdir, 'cli.synth')
        with open(synth_path, 'w') as fptr:
            fptr.write(SYNTH)
        outputs = []
        for name in ('a', 'b'):
            pcap_path = os.path.join(self.tmpdir, name + '.pcap')
            subprocess.check_output([sys.executable, os.path.join(SRC_DIR, 'flowsynth.py'), synth_path,
                                     '-f', 'pcap', '-w', pcap_path, '--display', 'json',
                                     '--no-filecontent', '--seed', '99'])
            outputs.append(self.read_bytes(pcap_path))
        self.assertEqual(outputs[0], outputs[1])


class TestStartTime(FlowsynthTestCase):

    def first_times(self, path):
        return [float(pkt.time) for pkt in rdpcap(path)][:2]

    def test_parse_start_time(self):
        parse = flowsynth.parse_start_time
        self.assertEqual(parse('1700000000'), 1700000000)
        self.assertEqual(parse('1700000000.5'), 1700000000.5)
        self.assertEqual(parse('2026-11-14'), 1794614400)
        self.assertEqual(parse('2026-11-14T10:00:00Z'), 1794650400)
        self.assertEqual(parse('2026-11-14T10:00:00'), 1794650400)
        self.assertEqual(parse('2026-11-14 10:00:00.25'), 1794650400.25)
        self.assertEqual(parse('2026-11-14T10:00:00+02:00'), 1794650400 - 7200)
        self.assertEqual(parse('2026-11-14T10:00:00-0130'), 1794650400 + 5400)
        self.assertEqual(parse(datetime.datetime(2026, 11, 14, 10)), 1794650400)
        self.assertEqual(parse(1794650400), 1794650400)
        for bad in ('yesterday', '2026-13-01', '2026-11-14T25:00', 'nan', 'inf', '-5', '1960-01-01',
                    '2106-02-08', 2**32, -1, float('nan'), True, '2026-11-14T10:00:00+99:99'):
            self.assertRaises(ValueError, parse, bad)

    def test_start_time_with_seed(self):
        times = self.first_times(self.build(seed=1, start_time='2026-11-14T10:00:00Z'))
        self.assertAlmostEqual(times[0], 1794650400)
        self.assertAlmostEqual(times[1] - times[0], flowsynth.SEEDED_TIME_STEP, places=5)
        first = self.read_bytes(self.build(seed=1, start_time='2026-11-14T10:00:00Z', name='a'))
        second = self.read_bytes(self.build(seed=1, start_time=1794650400, name='b'))
        self.assertEqual(first, second)

    def test_start_time_without_seed(self):
        times = self.first_times(self.build(start_time=1700000000))
        self.assertAlmostEqual(times[0], 1700000000)

    def test_default_seeded_start_time_unchanged(self):
        self.assertAlmostEqual(self.first_times(self.build(seed=1))[0], 946684800)

    def test_cli_start_time(self):
        synth_path = os.path.join(self.tmpdir, 'cli.synth')
        pcap_path = os.path.join(self.tmpdir, 'cli.pcap')
        with open(synth_path, 'w') as fptr:
            fptr.write(SYNTH)
        cmd = [sys.executable, os.path.join(SRC_DIR, 'flowsynth.py'), synth_path, '-f', 'pcap', '-w', pcap_path, '-q']
        subprocess.check_output(cmd + ['--seed', '1', '--start-time', '2026-11-14T10:00:00Z'])
        self.assertAlmostEqual(self.first_times(pcap_path)[0], 1794650400)
        proc = subprocess.Popen(cmd + ['--start-time', 'yesterday'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, err = proc.communicate()
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b'Invalid start time', err)


    def test_start_time_microseconds(self):
        # a start a hair under a whole second must not write usec=1000000
        path = self.build(seed=1, start_time=1700000000.9999996)
        with open(path, 'rb') as fptr:
            data = fptr.read()
        sec, usec = struct.unpack('<II', data[24:32])
        self.assertEqual((sec, usec), (1700000001, 0))
        self.assertAlmostEqual(self.first_times(path)[1], 1700000001.001)

    def test_start_time_too_late_for_packets(self):
        self.assertRaises(flowsynth.SynTerminalError, self.build, seed=1, start_time=2**32 - 0.0005)


class TestCli(FlowsynthTestCase):

    def run_cli(self, synth, *args):
        synth_path = os.path.join(self.tmpdir, 'cli.synth')
        with open(synth_path, 'w') as fptr:
            fptr.write(synth)
        cmd = [sys.executable, os.path.join(SRC_DIR, 'flowsynth.py'), synth_path, '-f', 'pcap',
               '-w', os.path.join(self.tmpdir, 'cli.pcap')] + list(args)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        return proc.returncode, out

    def test_json_build_status(self):
        # the shape Dalton's Flowsynth UI reads
        rc, out = self.run_cli(SYNTH, '--display', 'json', '--no-filecontent')
        self.assertEqual(rc, 0)
        status = json.loads(out.decode())
        self.assertTrue(status['successful'])
        self.assertEqual(status['compiler']['packets'], 10)
        for key in ('app_version', 'input-file', 'output-file'):
            self.assertIn(key, status)

    def test_invalid_mac_json_error(self):
        rc, out = self.run_cli('flow f udp 1.1.1.1:1 > 2.2.2.2:2 (src_mac: 00:11;);\nf > (content:"x";);\n',
                               '--display', 'json')
        self.assertNotEqual(rc, 0)
        status = json.loads(out.decode())
        self.assertIn('src_mac', status['error'])

    def test_syntax_error_exits_nonzero(self):
        bad = 'flow f tcp 1.1.1.1:foo > 2.2.2.2:2;\nf > (content:"x";);\n'
        rc, out = self.run_cli(bad, '--display', 'json')
        self.assertNotEqual(rc, 0)
        status = json.loads(out.decode())
        self.assertFalse(status['successful'])
        self.assertIn('foo', status['error'])
        rc, _ = self.run_cli(bad, '-q')
        self.assertNotEqual(rc, 0)


class TestBuildState(FlowsynthTestCase):

    def test_model_built_twice(self):
        synth_path = os.path.join(self.tmpdir, 'twice.synth')
        pcap_path = os.path.join(self.tmpdir, 'twice.pcap')
        with open(synth_path, 'w') as fptr:
            fptr.write(SYNTH)
        model = flowsynth.Model(input=synth_path, output_format='pcap', output_file=pcap_path,
                                quiet=True, seed=5)
        model.build()
        first = self.read_bytes(pcap_path)
        model.build()
        self.assertEqual(self.read_bytes(pcap_path), first)

    def test_builds_are_independent(self):
        first = self.read_bytes(self.build(seed=3, name='a'))
        self.build('flow x udp 10.9.9.9:1 > 10.8.8.8:2;\nx > (content:"z";);\n', name='other')
        self.assertEqual(self.read_bytes(self.build(seed=3, name='c')), first)
        # each flow holds only its own events
        self.assertEqual(len(flowsynth.COMPILER_FLOWS['web'].timeline), 6)
        self.assertEqual(len(flowsynth.COMPILER_FLOWS['dns'].timeline), 2)

    def test_run_without_seed_or_start_time(self):
        # callers that build their own ARGS, without the 1.5 fields, still work
        synth_path = os.path.join(self.tmpdir, 'old.synth')
        pcap_path = os.path.join(self.tmpdir, 'old.pcap')
        with open(synth_path, 'w') as fptr:
            fptr.write(SYNTH)
        saved = flowsynth.ARGS
        flowsynth.ARGS = argparse.Namespace(input=synth_path, output_format='pcap', output_file=pcap_path,
                                            quiet=True, debug=False, display='text', no_filecontent=False)
        try:
            flowsynth.run(synth_path)
        finally:
            flowsynth.ARGS = saved
        self.assertEqual(len(rdpcap(pcap_path)), 10)

    def test_redeclared_flow(self):
        synth = ('flow f udp 10.0.0.1:1111 > 10.0.0.2:53;\n'
                 'f > (content:"a";);\n'
                 'flow f udp 10.0.0.1:2222 > 10.0.0.2:53;\n'
                 'f > (content:"b";);\n')
        pkts = rdpcap(self.build(synth))
        self.assertEqual([(p[UDP].sport, bytes(p[UDP].payload)) for p in pkts],
                         [(1111, b'a'), (2222, b'b')])


if __name__ == '__main__':
    unittest.main()
