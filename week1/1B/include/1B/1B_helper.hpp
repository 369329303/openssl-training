#pragma once

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;

#define BUFSIZE 1024

class MY_Cipher {
public:
  MY_Cipher();
  ~MY_Cipher();
  int Init(int enc, const char *algorithm, const unsigned char *key,
           const unsigned char *iv);
  int Update(unsigned char *outbuf, int *outlen, const unsigned char *inbuf,
             int inlen);
  int Final(unsigned char *outbuf, int *outlen);

private:
  EVP_CIPHER *cipher = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
};

class MY_Digest {
public:
  MY_Digest();
  ~MY_Digest();
  int Init(const char *mname);
  int Update(const unsigned char *inbuf, int inlen);
  int Final(unsigned char *digest, int *digest_len);
  int SignInit(const char *mname, EVP_PKEY *pkey);
  int SignUpdate(const unsigned char *inbuf, int inlen);
  int SignFinal(unsigned char *sig, size_t *sig_len);

private:
  EVP_MD *md = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *mdctx = NULL;
  EVP_PKEY_CTX *pctx = NULL;
};

/* bin转换为hex */
int bin2hex(unsigned char *dst, int *pd, unsigned char *src, int s);

/* hex转换为bin */
int hex2bin(unsigned char *dst, int *pd, unsigned char *src, int s);
