#include "2C/create_csr.h"
#include "2C/2C_helper.h"

/* 从keyfile中读取私钥 */
EVP_PKEY *load_key(const char *keyfile, const char *format) {
  BIO *key = NULL;
  EVP_PKEY *pkey = NULL;
  key = BIO_new_file(keyfile, "rb");
  if (!key) {
    fprintf(stderr, "ERROR, BIO_new_file %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 读取bio中读取私钥 */
  pkey = strncmp(format, "PEM", 3)
             ? d2i_PrivateKey_bio(key, NULL)
             : PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
  if (!pkey) {
    fprintf(stderr, "ERROR, Read PrivateKey %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  return pkey;
}

int create_csr(const char *algorithm, const char *keyfile, const char *outfile,
               const char *format, char *subject) {
  X509_REQ *req = NULL;
  char *oformat = "PEM";
  /* 从文件中读取私钥 */
  EVP_PKEY *pkey = load_key(keyfile, oformat);

  const EVP_MD *md = EVP_get_digestbyname(algorithm);
  if (!md) {
    fprintf(stderr, "ERROR, EVP_get_digestbyname %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 创建一个X509的证书请求 */
  req = X509_REQ_new();
  if (!req) {
    fprintf(stderr, "ERROR, X509_REQ_new %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 0x1000 -- UTF8 */
  /* 向X509证书请求中添加私钥和DN项,并指定格式为UTF8 */
  make_REQ(req, pkey, subject, 0, 1, 0x1000);
  subject = NULL;

  STACK_OF(OPENSSL_STRING) *sigopts = NULL;

  /* 添加摘要信息 */
  if (1 != do_X509_REQ_sign(req, pkey, md, sigopts)) {
    fprintf(stderr, "ERROR, do_X509_REQ_sign %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 创建一个写bio */
  BIO *out = BIO_new_file(outfile, "wb");
  if (!out) {
    fprintf(stderr, "ERROR, BIO_new_file %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 将req写入到bio中 */
  if (0 == strncmp(format, "PEM", 3)) {
    /* PEM 格式 */
    if (1 != PEM_write_bio_X509_REQ(out, req)) {
      fprintf(stderr, "ERROR, PEM_write_bio_X509 %s.\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }
  } else {
    /* DER 格式 */
    if (1 != i2d_X509_REQ_bio(out, req)) {
      fprintf(stderr, "ERROR, i2d_X509_REQ_bio %s.\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }
  }

  return 0;
}
