Name: Sriharshini Duggirala
UID: 804784890

High Level Design:

In this project I implemented a simple router. The router received raw Ethernet frames and was able to process and forward them based on a given static routing table. I implemented the following functions in order to complete this project:

handlePacket():
This function was called when the router received a packet.
  - If the packet was of type ARP:
    - If it was an ARP request, the router generated an ARP response with its MAC address and sent it back to the sender.
    - If it was an ARP response packet, the router first added the IP-MAC pair to the ArpCache. Then it found all queued packets that were supposed to go to the source and sent them. Finally it removed the ARP request from the list.
  - If the packet was of type IP:
    - It made sure the packet was valid and that its destination was not the router.
    - Once all these specifications were met the router chose the correct interface to send the packet through based on its routing table and forwarded the packet in the right direction.

periodicCheckArpRequestsAndCacheEntries():
This function had 2 main purposes:
  1. Make sure an ARP request is sent at most 5 times if it does not receive a response. If no response is received after 5 requests the request is taken out of the list and all pending packets are discarded.
  2. Remove all stale entries from the ArpCache.

lookup() For the RoutingTable:
This function served the important purpose of returning the right entry in the routing table using "longest matching prefix" algorithm.


Problems & Solutions:

Problems with the code:
1. It was hard to figure out where to start since there were a lot of functions already implemented for us. At first I found it difficult to navigate the code, but when I went back and read the spec more thoroughly everything became much clearer.
2. ARP request: Figuring out what the ARP request was hard for me, but once I went back and read the notes as well as went through the arp_hdr struct I was able to complete this section of the project.
3. htons() & ntohs(): I was unsure of when I was supposed to use these functions. I ran into errors, because I did not use htons() when putting setting the ether_type in the ethernet header. I was able to debug and figure out my errors by using the print functions defined in utils.cpp.
4. ArpCache: I had some trouble deleting from the arpcache initially, because I was deleting and then still while iterating through the list. To fix this I iterated through the list first and created an vector of entries I needed to remove then removed the entries from the vector.

Problems w/ the environment:
I ran into many problems while trying to set up the environment, because I had a very new version of MACOS, I then looked at the TAs FAQ and found that a solution was to download an Ubuntu VM with the new version of virtualbox and then download the old version of virtualbox within that. However, when I tried doing this it was not only very slow, but I was also getting many permission errors when running vagrant up. To resolve this problem I realized that I had my old laptop and used that instead. Worked like a charm!
