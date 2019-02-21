flow default tcp [2606:2800:220:1:248:1893:25c8:1946]:44123 > [2607:f8b0:4004:800::200e]:80 (tcp.initialize;);
default > (content:"GET / HTTP/1.1\x0d\x0aHost:google.com\x0d\x0aUser-Agent: DogBot\x0d\x0a\x0d\x0a";);
default < (content:"HTTP/1.1 200 OK\x0d\x0aContent-Length: 300\x0d\x0a\x0d\x0aWelcome to Google.com!\x0d\x0a\x0d\x0a";);
