#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <sdn_interface_ops.h>

int SetupInterFaceParams(char *pcDev, int iAddrFamily, char *pcIPAdrress, char *pcNetMask, char * pcMacAddr, int iMTU, char *szStatus)
{
	struct ifreq ifr;
	int fd = -1, ret = -1;
	struct sockaddr_in *addr = NULL;
	if (!pcIPAdrress || !pcDev)
		return -1; 
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		perror("Error Creating Socket");
		strncpy(szStatus, "Error Creating Socket", strlen("Error Creating Socket") + 1);
		return -2;
	}
	if (iAddrFamily == AF_INET)
		ifr.ifr_addr.sa_family = AF_INET;
	else
		ifr.ifr_addr.sa_family = AF_INET6;
	memcpy(ifr.ifr_name, pcDev, IFNAMSIZ-1);
	addr=(struct sockaddr_in *)&ifr.ifr_addr;
	if ((ret = inet_pton(AF_INET, pcIPAdrress, &addr->sin_addr)) != 1)
	{
		//Failed to get ip from 
	}
	if ((ret = ioctl(fd, SIOCSIFADDR, &ifr)) < 0)
	{
		// Failed Set IP
	}
	addr=(struct sockaddr_in *)&ifr.ifr_netmask;
	if ((ret = inet_pton(AF_INET, pcNetMask, &addr->sin_addr)) != 1)
	{
		// Failed to get Netmask
	}
	ifr.ifr_flags = IFF_POINTOPOINT|IFF_NOARP|IFF_MULTICAST;	
	if ((ret = ioctl(fd, SIOCGIFFLAGS, &ifr)) < 0)
	{
	}
	if ((ret = ioctl(fd, SIOCSIFNETMASK, &ifr)) < 0)
	{
		// Set NetMask
	}
	if (pcMacAddr)
	{
		ifr.ifr_ifru.ifru_hwaddr.sa_family = ARPHRD_ETHER;
		memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, pcMacAddr,6);
		if (ioctl(fd,SIOCSIFHWADDR,(void *)&ifr) < 0) 
		{
			// Set Mac Address Failed
		}
	}
	ifr.ifr_ifru.ifru_mtu = iMTU;
	if (ioctl(fd,SIOCSIFMTU,(void *)&ifr) < 0) 
	{
		// Failed to Set MTU
	}
	// Set IF UP and Flags
	ifr.ifr_flags = IFF_UP|IFF_POINTOPOINT|IFF_RUNNING|IFF_NOARP|IFF_MULTICAST;	
	if ((ret = ioctl(fd, SIOCGIFFLAGS, &ifr)) < 0)
	{
		// Set Tunnel  Mode Failed
	}
	close(fd);
	return 0;	
}


