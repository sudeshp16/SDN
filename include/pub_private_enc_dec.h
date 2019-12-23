#ifndef __PUB_PRIVATE_ENCRPYT_H__
#define __PUB_PRIVATE_ENCRPYT_H__
#include <openssl/rsa.h>

RSA * GenerateRSA(const unsigned char * key,int public);

#endif //	__PUB_PRIVATE_ENCRPYT_H__
