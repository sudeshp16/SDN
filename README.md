# SDN
# A Client Server SCTP based VPN with TLS support using Openssl
###########################
## The Communication's Transport Protocol chosen is SCTP as it supports ,
mulihoming inherently , so it can even suffice a change in IP address , in the
transport Layer Protocol itself .

######## The Client Uses a TUN/TAP Adapter to create an interface for communication
like a Local Network (VPN), the data transmitted over this interface is transmitted through 
SSL VPN, now the underlying Transport Layer Protocol it supports is TCP, UDP and the 
SCTP.

########## The client is Facing issues like Client uses a high CPU , utilisation.
Hence Need Active developers and Testers for the same. 
