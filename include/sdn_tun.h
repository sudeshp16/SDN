#ifndef __CLI_TUN_H__
#define __CLI_TUN_H__

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#ifdef __cpluscplus
#define extern "C" {
#endif

int tun_alloc(char *dev, int flags);
int tun_set_queue(int fd, int enable);
#ifdef __cpluscplus
}
#endif
#endif // __CLI_TUN_H__
