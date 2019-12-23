#ifndef __SDN_ROUTE_H__
#define __SDN_ROUTE_H__
#include <string.h>
//int SetupIPAddress(char *pcDev, int iAddrFamily, char *pcIPAdrress, char *pcNetMask, char *szStatus);
int SetupInterFaceParams(char *pcDev, int iAddrFamily, char *pcIPAdrress, char *pcNetMask, char * pcMacAddr, int iMTU, char *szStatus);

#endif
