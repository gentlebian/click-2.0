// my-NAT.click

// This configuration is a simple construction with four source addr-
// esses trying to sending through a NAT to two different destination
// addresses. It is just for simple testing for modified IPRewriter t
// o support sending table items to remote database.

// Set up NAT
rw :: IPRewriter(pattern 1.0.0.1 5000-20000 - - 2 0, pattern 1.0.0.1 5000-20000 - - 3 1, UDP_TIMEOUT 1);

// Generating input packets
InfiniteSource(\<00000000111111112222222233333333444444445555>, 100)
	-> UDPIPEncap(192.168.4.4, 50, 152.14.13.1, 80, 1)
	-> IPPrint(source1)
	-> [0]rw;

InfiniteSource(\<00000000111111112222222233333333444444445555>, 100)
	-> UDPIPEncap(192.168.4.3, 51, 152.14.13.1, 80, 1)
	-> IPPrint(source2)
	-> [0]rw;

InfiniteSource(\<00000000111111112222222233333333444444445555>, 100)
	-> UDPIPEncap(192.168.4.2, 52, 152.14.13.1, 80, 1)
	-> IPPrint(source3)
	-> [0]rw;


InfiniteSource(\<00000000111111112222222233333333444444445555>, 100)
	-> UDPIPEncap(192.168.4.1, 53, 152.14.13.1, 80, 1)
	-> IPPrint(source3)
	-> [1]rw;
// Generating packets and sending to NAT(OuterNet)
//rw[0] -> IPPrint(rw0) -> Discard;
rw[0] -> rw[2] -> IPPrint(rw1) -> Discard;
rw[1] -> rw[3] -> IPPrint(attack) -> Discard;
// NAT handling packets

