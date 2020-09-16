# PINGCATCHER
![](https://github.com/Har1743/pingcatcher/blob/master/ping/logo-1.png)  

PINGCATCHER is a tool used to capture ICMPv4 and ICMPv6 packets.  
  
## Why PINGCATCER ?  

As while working on **tcpdump** or any other packet capturing tool there I was not able to capture or get ICMP packets information properly so decided to build this **pingcatcher** tool which helps to capture ICMPv4 and ICMPv6 packets properly with a proper GUI which helps user to get info about ICMP packets properly and it always works and it is also easy to use.  

## How it works ?

It firstly creates a raw socket which recieves ethernet frame and **unpacks** that recieved **ethernet frame**, then further it checks payload for **IPv4** and **IPv6** packet. Upon checking then it further **unpacks** the **IP** packet and check payload for **ICMPv4** and **ICMPv6** packet, if it an **ICMP** then it check whether it's an **ICMP request or reply** and then show the information according to the **ICMP** version.      



  

