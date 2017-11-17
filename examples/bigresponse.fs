flow default tcp 192.168.238.112:13749 > 1.2.3.4:80 (tcp.initialize;);

default > 	(
			content:"GET\x20/\x20HTTP/1.1\x0d\x0aHost\x3a\x20suricata-ids.org"; content:"\x0d\x0a\x0d\x0a";  
			);

default < 	(
			content:"HTTP/1.1\x20200\x20OK\x0d\x0a"; 
			content:"\x0d\x0a\x0d\x0a"; 
			filecontent:"suricata-ids.org.html"
			);