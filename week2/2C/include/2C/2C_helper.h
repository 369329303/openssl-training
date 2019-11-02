#include "2C/2C_main.h"

int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *subj, int multirdn,
             int attribs, unsigned long chtype);

int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts);
