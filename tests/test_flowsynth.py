"""tests for flowsynth's generated MACs, sequence numbers, ports and seeding

run with: python -m unittest discover tests  (or: python -m pytest tests)
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src')
sys.path.insert(0, SRC_DIR)

import flowsynth  # noqa: E402
from scapy.all import Ether, IP, TCP, UDP, rdpcap  # noqa: E402

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

    def build(self, synth=SYNTH, seed=None, name='out'):
        """build a synth via the Model API; return the pcap path"""
        synth_path = os.path.join(self.tmpdir, name + '.synth')
        pcap_path = os.path.join(self.tmpdir, name + '.pcap')
        with open(synth_path, 'w') as fptr:
            fptr.write(synth)
        flowsynth.Model(input=synth_path, output_format='pcap', output_file=pcap_path,
                        quiet=True, seed=seed).build()
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
        syn, synack, ack = tcp_pkts[:3]
        self.assertEqual(syn.ack, 0)
        self.assertEqual(synack.ack, (syn.seq + 1) % 2**32)
        self.assertEqual((ack.seq, ack.ack), ((syn.seq + 1) % 2**32, (synack.seq + 1) % 2**32))
        next_seq = {80: ack.ack, 44123: ack.seq}       # keyed by sending port
        for pkt in tcp_pkts[3:]:
            peer = 44123 if pkt.sport == 80 else 80
            self.assertEqual(pkt.seq, next_seq[pkt.sport], "bad seq: %r" % pkt)
            self.assertEqual(pkt.ack, next_seq[peer], "bad ack: %r" % pkt)
            next_seq[pkt.sport] = (pkt.seq + len(pkt.payload)) % 2**32

    def test_seq_ack_consistent(self):
        tcp_pkts = self.tcp_packets(self.build())
        # handshake, request + ACK, response + ACK, bare ACK
        self.assertEqual(len(tcp_pkts), 8)
        self.assert_seq_ack_consistent(tcp_pkts)

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


if __name__ == '__main__':
    unittest.main()
