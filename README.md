# Flowsynth #

Flowsynth is a tool for rapidly modeling network traffic. Flowsynth can be used to generate text-based hexdumps of packets as well as native libpcap format packet captures.

## Installation and Usage Overview ##

Flowsynth has been tested on Python 2.7 and Python 3.

### Python Script ###

The following python modules are required to run Flowsynth:

+	argparse
+	scapy

To install requirements with pip:

    pip install -r requirements.txt

Usage:

    usage: flowsynth.py [-h] [-f OUTPUT_FORMAT] [-w OUTPUT_FILE] [-q] [-d]
                        [--display {text,json}] [--no-filecontent]
                        input

    positional arguments:
      input                 input files
    
    optional arguments:
      -h, --help            show this help message and exit
      -f OUTPUT_FORMAT      Output format. Valid output formats include: hex, pcap
      -w OUTPUT_FILE        Output file.
      -q                    Run silently
      -d                    Run in debug mode
      --display {text,json}
                            Display format
      --no-filecontent      Disable support for the filecontent attribute

### Python Module ###

Flowsynth can also be installed and used as a Python module:

    pip install flowsynth

Example usage:

    import flowsynth
    fsmodel = flowsynth.Model(input="my.synth", output_file="out.pcap", output_format="pcap")
    fsmodel.build()

The Model class function `build()` executes flowsynth and the class constructor takes the same arguments as the script (see above):

    class Model():
        def __init__(self, input, output_format="pcap", output_file="", quiet=False, debug=False, display="text", no_filecontent=False):
        ...

*Note:* Because of the current less-than-ideal use of global variables instead of class variables, if more than one Model object is used concurrently, there will be issues. Hopefully this limitation will be remedied in a future release.

## How it works ##

Flowsynth uses a syntax language to describe network flows. The syntax language is made up of individual *instructions* that are parsed by the application and are grouped into *events*, which are a logical representation of the *instructions* in the network domain. After all *instructions* have been parsed, the *events* are iterated over and converted into *packets*, which are the real-world representation of the traffic on the wire.

These three phases are referred to as the *parsing phase*, *rendering phase*, and the *output phase*.

Take the following synfile as an example:

	flow default tcp myhost.corp.acme.net:12323 > google.com:80 (	tcp.initialize; );
	default > ( content:"GET / HTTP/1.1\x0d\x0a"; content:"Host: google.com\x0d\x0a\x0d\x0a"; );
	default < ( content:"HTTP/1.1 200 OK"; );

This sample contains two types of instructions: Flow declarations and event declarations. The first line (*flow default tcp...*) declares to Flowsynth that a flow is being tracked between myhost.corp.acme.net and google.com. The flow name is *default*. All events that apply to this flow will use this name (*default*) to identify which flow they apply to. The third argument specifies which protocol the flow will use. In this case it's *tcp*. Next we specify the source and destination addresses and ports. Finally, an optional attributes section is included at the end. The *tcp.initialize* attribute is included, which tells Flowsynth to automatically generate a three-way handshake for this flow. It's worth nothing that each attribute and line should be closed with a semicolon (;), as shown above. When this flow declaration instruction is parsed by Flowsynth the application will automatically generate event entries in the compiler timeline to establish a three way handshake.

Next, Flowsynth will parse the event declaration *default > ( content ...*. Flowsynth will immediately identify that this event declaration belongs to the 'default' flow that was just declared. Once this event is associated with the flow any protocol specific values (like TCP SEQ and ACK numbers) will automatically be applied to the event. The directionality for this specific event is '>', or TO_SERVER. Once the parent flow and directionality have been established Flowsynth will parse the optional attributes section. Just like the flow declaration, each optional attribute must be closed with a semicolon (;). The two 'content' attributes are used to specify the packet's payload. In this case, a HTTP request is being rendered. Flowsynth will read these instructions and generate an entry in the compiler timeline for this event.

The last event declaration that is parsed by the application shows the server's response to the client. Using the same methods described above, Flowsynth will parse the event declaration and add it to the compiler timeline.

Once all the instructions have been parsed and processed, Flowsynth iterates over the compiler timeline and renders any events to native packets. In this phase of the application several important things happen:

1.   Protocol-specific intelligence, like TCP SEQ/ACK calculations, and ACK generation take place.
2.   Specific features of attributes, like converting '*\x3A*' to '*:*' take place.

Once all of the events have been rendered to native pcaps the output phase occurs. During the output phase the native packets are delivered to the user in one of the two output formats, as a hexdump, or as a native PCAP file.

## Usage ##

	flowsynth.py input.syn

In this most basic example, Flowsynth will read input.syn and output the resulting hexdump to the screen. By default Flowsynth will use 'hex' format.

	flowsynth.py input.syn -f pcap -w /tmp/test.pcap

In this example, Flowsynth reads input.syn and outputs a libpcap formatted .pcap file to /tmp/test.pcap


## Syntax ##
All Flowsynth syntax files are plain-text files. Currently three types of instructions are supported.

+	Comments
+	Flow Declarations
+	Event Declarations

As new features are added, this syntax reference will be updated.

### Comments ###

Comments are supported using the *#* symbol.

	# This is a synfile comment

### Flows ###

#### Declaring a Flow ####
You can declare a flow using the following syntax:

	flow [flow name] [proto] [src]:[srcport] [directionality] [dst]:[dstport] ([flow options]);


*src* and *dst* can be IPv4 addresses, IPv6 addresses, or resolvable domain names.  For IPv6, the address(es) must be enclosed in square brackets ('[' and ']').

The following flow declaration would describe a flow going from a computer to google.com:

    flow my_connection tcp mydesktop.corp.acme.com:44123 > google.com:80 (tcp.initialize;);

The following flow declaration would describe a flow going from a computer to a DNS server:

    flow dns_request udp  mydesktop.corp.acme.com:11234 > 8.8.8.8:53;

The following flow declaration would describe a flow using IPv6 addresses:

    flow default tcp [2600:1337:2800:1:248:1893:25c8:d1]:31337 > [2600:1337:2800::f1]:80 (tcp.initialize;);

For the interim, directionality should always be specified as to server: >

If a DNS record is specified in the flow declaration (instead of an explicit IP address) then Flowsynth will resolve the DNS entry at the time of the flow's declaration. The first A record returned for DNS entry will be used as the IP address throughout the session. The DNS query and response is not included in the output.

#### Flow Attributes #####
The following flow attributes are currently supported:

##### tcp.initialize #####
The *tcp.initialize* attribute informs Flowsynth that the flow should have an autogenerated TCP three-way handshake included in the output. The handshake is always added relative to the location of the flow declaration in the synfile.

usage:

`(tcp.initialize; );`

##### src_mac #####
The *src_mac* attribute explicitly sets the MAC address for packets from the flow source. If no MAC is supplied, a random one is chosen.

usage:
`(tcp.initialize; src_mac: 37:16:3a:4e:6a:12; );`

##### dst_mac #####
The *dst_mac* attribute explicitly sets the MAC address for packets from the flow destination. If no MAC is supplied, a random one is chosen.

usage:
`(tcp.initialize; dst_mac: 37:16:3a:4e:6a:13; );`


### Events ###

#### Transferring Data ####
Data can be transferred between hosts using two methods. The example below outlines a data exchange between a client and a webserver:

	my_connection > (content:"GET / HTTP/1.1\x0d\x0aHost:google.com\x0d\x0aUser-Agent: DogBot\x0d\x0a\x0d\x0a";);
	my_connection < (content:"HTTP/1.1 200 OK\x0d\x0aContent-Length: 300\x0d\x0a\x0d\x0aWelcome to Google.com!";);

In this example, the flow *my_connection* must have been previously declared. A single packet with the content specified will be transmitted from the client to the server. The following method is also accepted, however, this may change in the future as the syntax is formalized.:

	my_connection.to_server (content:"GET / HTTP/1.1\x0d\x0aHost:google.com\x0d\x0aUser-Agent: DogBot\x0d\x0a\x0d\x0a";);
	my_connection.to_client (content:"HTTP/1.1 200 OK\x0d\x0aContent-Length: 300\x0d\x0a\x0d\x0aWelcome to Google.com!";);

 Each content keyword within the () should be closed by a semicolon. Each line should also be closed with a semicolon. Failure to do so will generate a lexer error. Multiple content matches can also be used to logically seperate parts of the response, for example:

    # the commands below describe a simple HTTP request
    my_connection > (content:"GET / HTTP/1.1\x0d\x0aHost:google.com\x0d\x0a\x0d\x0a";);
    my_connection < (content:"HTTP/1.1 200 OK\x0d\x0aContent-Type: text/html\x0d\x0a\x0d\x0a"; content:"This is my response body.";);

#### Event Attributes ####
The following event attributes are currently supported:

+	content
+	filecontent
+	tcp.seq
+	tcp.ack
+	tcp.noack
+	tcp.flags.syn
+	tcp.flags.ack
+	tcp.flags.rst

##### Content Attribute #####
The *content* attribute is used to specify the payload of a packet. Content attributes must be enclosed in double quotes. Special characters can be expressed in hex, like: *\x0d\x0a*. Anything prefaced with \x will be converted from hex to its ascii representation. These translation takes place during the render phase.

Example:

	default > ( content: "GET / HTTP/1.1\x0d\x0a"; );

##### Filecontent Attribute #####
The *filecontent* attribute is used to specify a file that can be used as the payload of a packet. The value of a filecontent attribute is the file that will be read into the payload.

Example:

	default > ( content: "HTTP/1.1 200 OK\x0d\x0a\x0d\x0a"; filecontent: "index.html"; );

##### tcp.seq Attribute #####
The *tcp.seq* attribute lets you set the sequence number for the event's packet.

##### tcp.ack Attribute #####
The *tcp.ack* attribute lets you set the acknowledgement number for the event's packet.

##### tcp.noack Attribute #####
The *tcp.noack* attribute tells Flowsynth to not generate an ACK for this event.

##### tcp.flags.syn Attribute #####
The *tcp.flags.syn* attribute tells Flowsynth to force the packet to be a SYN packet.

##### tcp.flags.ack Attribute #####
The *tcp.flags.ack* attribute tells Flowsynth to force the packet to be an ACK packet.

##### tcp.flags.rst Attribute #####
The *tcp.flags.rst* attribute tells Flowsynth to force the packet to be a RST packet.

## Authors ###

+	Will Urbanski (will dot urbanski at gmail dot com)

#### Contributors ####

+	David Wharton
+	@2xyo
+	@bhaan
