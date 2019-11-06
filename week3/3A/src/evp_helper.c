#include "3A/evp_helper.h"

/* 从pkeyfile文件中读取公钥或私钥 */
EVP_PKEY *load_key(int seal, const char *pkeyfile) {
  BIO *key_bio = NULL;
  EVP_PKEY *pkey = NULL;

  key_bio = BIO_new_file(pkeyfile, "rb");
  if (!key_bio) {
    fprintf(stderr, "ERROR, BIO_new_file %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 读取bio中读取公钥或私钥 */
  /* 这个地方要注意,创建信封要用公钥,解信封要用私钥 */
  pkey = seal ? PEM_read_bio_PUBKEY(key_bio, NULL, NULL, NULL)
              : PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
  if (!pkey) {
    fprintf(stderr, "ERROR, PEM_read_bio_PrivateKey/PUBKEY %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  BIO_free(key_bio);

  return pkey;
}
