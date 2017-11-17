flow alpha_only tcp 10.10.10.10:23 > 1.2.3.4:23 (tcp.initialize;);
flow numbers_only tcp 192.168.9.10:23 > 5.6.7.8:23 (tcp.initialize;);

alpha_only > (content:"AAAAAAAAAAAAAAA"; );
numbers_only > (content:"000000000000000"; );

alpha_only < (content:"BBBBBBBBBBBBBBB"; );
numbers_only < (content:"111111111111111"; );

alpha_only > (content:"CCCCCC"; );
numbers_only > (content:"222222222222222"; );
alpha_only > (content:"CCCCCC"; );