/*@Description : This File contains code to Read RSA key
 *  Files and Encrypt and Decrypt Strings Using the Private
 *  and Public Key.
 *
 * @Author Sudesh Patil.
 *
 * @date 03 June 2019
 * */

//////////////////////////////////////////////////////////////////////
//			I 	N	C 	L 	U	D 	E 	S
/////////////////////////////////////////////////////////////////////

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <errno.h>
#include <pub_private_enc_dec.h>


/*@fn GenerateRSA 
 * @Description: 
 * 		This Function Generates RSA structure pointer ,
 * 		which Can be used to read Public and Private key.
 *
 * @Params:	Key : String containing the Key.
 * 			Type: unsigned char pointer.
 *
 * @Author : Sudesh Patil   
 * */

RSA * GenerateRSA(const unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio  = NULL;
	char error_buf[256];
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        perror("Failed to create key BIO ");
        return NULL;
    }
    if(public)
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    else
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    if(rsa == NULL)
	{
		ERR_error_string(ERR_get_error(), error_buf);
		perror(error_buf);
	}
    return rsa;
}

/*@Fn PublicEncrypt
 *
 * @Description: 
 * 		This Function Encrypts a unsigned char string using the Public Key
 * 		File Specified
 * @Params:
 * 		data:  The unencrypted Data to be encrypted.
 * 		Type:	unsigned char pointer.
 * 		data_len: The length of the data.
 * 		Type: int
 * 		key: The Key File which is used to Encrypt the data.
 * 		Type: char pointer.
 * 		encrypted: The Encrypted String of data.
 * 		Type: char pointer.
 *
 * 	@Author: Sudesh Patil
 *
 * 	@Date 03 June 2019.*/
int PublicEncrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = NULL;
	char error_buf[256];
    int result = -1;
	int padding = RSA_PKCS1_PADDING;
	rsa = GenerateRSA(key,1);
	if (rsa)
	{
		result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
		if (result == -1)
		{
			ERR_error_string(ERR_get_error(), error_buf);
			perror(error_buf);
		}
	}
    return result;
}


/*@Fn 
 *
 * @Description: 
 * 		This Function Decrypts a unsigned char string using the Private Key
 * 		File Specified
 * @Params:
 * 		data:  The encrypted Data to be decrypted.
 * 		Type:	unsigned char pointer.
 * 		data_len: The length of the data.
 * 		Type: int
 * 		key: The Key File which is used to Encrypt the data.
 * 		Type: char pointer.
 * 		decrypted: The decrypted String of data.
 * 		Type: char pointer.
 *
 * 	@Author: Sudesh Patil
 *
 * 	@Date 03 June 2019.*/
int PrivateDecrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = NULL;
    int  result = 0;
	int padding = RSA_PKCS1_PADDING;
	char error_buf[256];
	rsa = GenerateRSA(key,0);
	if (rsa)
	{
		result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
		if (result == -1)
		{
			ERR_error_string(ERR_get_error(), error_buf);
			perror(error_buf);
		}
	}
    return result;
}
