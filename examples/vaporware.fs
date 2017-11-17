flow default tcp 192.168.238.112:13749 > 172.16.239.127:80 (tcp.initialize;);

default > 	(
			content:"GET\x20/\x20HTTP/1.1\x0d\x0aHost\x3a\x20google.com"; content:"\x0d\x0aContent-Length: 22"; 
			content:"\x0d\x0a\x0d\x0a"; 
			content:"q=duke+nukem+forever+release+date"; 
			);

default < 	(
			content:"HTTP/1.1\x20404\x20Not\x20Found\x0d\x0aServer\x3a\x202.7\x20Android\x202.3\x20Gingerbread"; 
			content:"\x0d\x0aContent-Length: 72"; 
			content:"\x0d\x0a\x0d\x0a"; 
			content:"<html><body>The\x20software\x20you\x20requested\x20could\x20not\x20be\x20found!</body></html>";
			);