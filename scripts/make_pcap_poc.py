#!/usr/bin/env python
"""
make_pcap_poc.py - A tool that takes a file and creates a pcap of that
file being downloaded over HTTP. Originally created to make
pcaps from proof of concept exploit files related to particular CVEs.
This uses flowsynth to make the pcap (pip install flowsynth).
"""
# Copyright 2017 Secureworks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import glob
import sys
import re
import random
from mimetypes import MimeTypes
import imp
import shlex
import tempfile

DEBUG = True

file_from_external_net = True
HTTP_PORT = 80
cve_re = re.compile(r"(?P<CVE>CVE[\x2D\x5F]?\d{2,4}[\x2D\x5F]?\d{1,6})", re.IGNORECASE)

def print_debug(msg):
    global DEBUG
    if msg and DEBUG:
        print("\t%s" % msg)

def print_error(msg):
    print("ERROR! %s" % msg)
    sys.exit(1)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #
# change to wherever you have flowsynth.py if not in import path #
flowsynth_script = os.path.join("..", "src", "flowsynth.py")

try:
    import flowsynth
except:
    print_debug("Could not import flowsynth, trying load source from \'%s\'." % flowsynth_script)
    if not os.path.isfile(flowsynth_script):
        print_error("FlowSynth script file \'%s\' does not exist! Update the path in this script (%s)." % (flowsynth_script, sys.argv[0]))
    try:
        flowsynth = imp.load_source('flowsynth', flowsynth_script)
    except Exception as e:
        print_error("Could not import flowsynth or load from file \'%s\'. Error:\n%s" % (flowsynth_script, e))

def usage():
    print("Usage: make_pcap_poc.py <poc_file> [<output_file>]")
    sys.exit(1)

if len(sys.argv) < 2:
    usage()

poc_file = os.path.abspath(sys.argv[1])

if not os.path.isfile(poc_file):
    print_error("PoC file \'%s\' does not exist!" % poc_file)

# try to get CVE based on name and/or path
cve = "CVE-unknown"
result = cve_re.search(os.path.abspath(poc_file))
if result:
    cve = result.group('CVE')

print("Creating pcap for %s" % cve)

if len(sys.argv) > 2:
    pcap_file = sys.argv[2]
else:
    pcap_file = "%s_%s.pcap" % (cve, os.getpid())

# make the flowsynth file
fs_fh = tempfile.NamedTemporaryFile(mode='w')
print_debug("FlowSynth file: %s" % fs_fh.name)

client_ip = "192.168.%d.%d" % (random.randint(0,255), random.randint(0,255))
server_ip = "172.%d.%d.%d" % (random.randint(16,31), random.randint(0,255), random.randint(0,255))
if not file_from_external_net:
    client_ip_temp = client_ip
    client_ip = server_ip
    server_ip = client_ip_temp
print_debug("Client IP: %s" % client_ip)
print_debug("Server IP: %s" % server_ip)

# get file size
file_size = os.path.getsize(poc_file)
print_debug("Using file size: %d" % file_size)

# get MIME type
mime_type = MimeTypes().guess_type(os.path.basename(poc_file))[0]
if not mime_type:
    mime_type = 'text/html'

print_debug("Using MIME type \'%s\'" % mime_type)

fs_fh.write("flow default tcp %s:%d > %s:%d (tcp.initialize;);\n" % (client_ip, random.randint(1025, 65535), server_ip, HTTP_PORT))
fs_fh.write("""default > (content:\"GET /%s/%s HTTP/1.1\\x0d\\x0aUser-Agent: FlowSynth Puncha Yopet Edition (make_pcap_poc.py)\\x0d\\x0aTest-For: %s\\x0d\\x0a\\x0d\\x0a\";);\n""" % (cve, os.path.basename(poc_file), cve))
fs_fh.write("""default < (content:\"HTTP/1.1 200 OK\\x0D\\x0AServer: FlowSynth (Petty Petter)\\x0D\\x0AContent-Type: %s\\x0D\\x0AContent-Length: %d\\x0D\\x0A\\x0D\\x0A\"; filecontent:\"%s\";);\n""" % (mime_type, file_size, poc_file))

# important - reset file pointer so we can read from the top
fs_fh.seek(0)

model = flowsynth.Model(input=fs_fh.name, output_format="pcap", output_file=os.path.abspath(pcap_file))

model.build()

fs_fh.close()

print("Done. Wrote pcap to:\n%s" % pcap_file)

