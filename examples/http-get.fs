flow default tcp example.com:44123 > google.com:80 (tcp.initialize;);
default > (content:"GET / HTTP/1.1\x0d\x0aHost:google.com\x0d\x0aUser-Agent: DogBot\x0d\x0a\x0d\x0a";);
default < (content:"HTTP/1.1 200 OK\x0d\x0aContent-Length: 26\x0d\x0a\x0d\x0aWelcome to Google.com!\x0d\x0a\x0d\x0a";);
