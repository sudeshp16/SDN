#include <sdn_tun.h>

int tun_alloc(char *dev, int persist_flag)
{

  	struct ifreq ifr;
  	int err, fd = -1, i = 0;
  	char *clonedev = "/dev/net/tun";
  	memset(&ifr, 0, sizeof(ifr));
  	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  	if (*dev) 
  	{
    	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}
  	else	// Set Default Adapter Name
	{
		strncpy(ifr.ifr_name, "tun%d",5);
	}
  	if( (fd = open(clonedev , O_RDWR)) < 0 ) 
	{
    	  perror("Opening /dev/net/tun");
	close(fd);
    	return -1;
  	}
  	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) 
  	{
    		perror("ioctl(TUNSETIFF) ");
		printf("Errno %d\n",errno); 
		close(fd);
    		return -2;
  	}
  	printf("Interface name %s\n", ifr.ifr_name);
	strncpy(dev, ifr.ifr_name, strlen(ifr.ifr_name)+1);
  	return fd;
}

int tun_set_queue(int fd, int enable)
{
      struct ifreq ifr;
      memset(&ifr, 0, sizeof(ifr));

      if (enable)
         ifr.ifr_flags = IFF_ATTACH_QUEUE;
      else
         ifr.ifr_flags = IFF_DETACH_QUEUE;

      return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}
