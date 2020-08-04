flow dns_request udp 10.200.31.12:11234 > 8.8.8.8:53;

dns_request > (
    # transaction ID (should be random two bytes)
    content:"\xBA\xBE";

    # flags; set as appropriate (see RFC)
    content:"\x01\x00";

    # Number of questions
    content:"\x00\x01";

    # answer resource records
    content:"\x00\x00";

    # authority resource records
    content:"\x00\x00";

    # additional resource records
    content:"\x00\x00";

    # queries
    # name (len, value, len, value, ... null)
    content:"\x05linux\x16georgepburdell-desktop\x04corp\x04acme\x03com\x00";

    # type (\x0001 is A)
    content:"\x00\x01";

    # class (0x0001 is IN/Internet)
    content:"\x00\x01";
);
