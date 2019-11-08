#include "1B/1B_helper.hpp"

// MY_Cipher 构造函数
MY_Cipher::MY_Cipher() { ctx = EVP_CIPHER_CTX_new(); }

// MY_Cipher 析构函数
MY_Cipher::~MY_Cipher() { EVP_CIPHER_CTX_free(ctx); }

// Cipher 初始化
int MY_Cipher::Init(int enc, const char *algorithm, const unsigned char *key,
                    const unsigned char *iv) {
  cipher = (EVP_CIPHER *)EVP_get_cipherbyname(algorithm);
  if (1 != EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc)) {
    fprintf(stderr, "ERROR: EVP_CipherInit_ex %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

// Cipher 加密
int MY_Cipher::Update(unsigned char *outbuf, int *outlen,
                      const unsigned char *inbuf, int inlen) {
  if (1 != EVP_CipherUpdate(ctx, outbuf, outlen, inbuf, inlen)) {
    fprintf(stderr, "ERROR: EVP_CipherUpdate %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

// Cipher 结束
int MY_Cipher::Final(unsigned char *outbuf, int *outlen) {
  if (1 != EVP_CipherFinal_ex(ctx, outbuf, outlen)) {
    fprintf(stderr, "ERROR: EVP_CipherFinal_ex %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

// MY_Digest 构造函数
MY_Digest::MY_Digest() { mdctx = EVP_MD_CTX_new(); }

// MY_Digest 析构函数
MY_Digest::~MY_Digest() { EVP_MD_CTX_free(mdctx); }

// Digest 初始化
int MY_Digest::Init(const char *mname) {
  md = (EVP_MD *)EVP_get_digestbyname(mname);
  if (NULL == md) {
    fprintf(stderr, "ERROR: EVP_get_digestbyname %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  /* 初始化mdctx */
  if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
    fprintf(stderr, "ERROR: EVP_DigestInit_ex %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

// Digest 更新
int MY_Digest::Update(const unsigned char *inbuf, int inlen) {
  if (1 != EVP_DigestUpdate(mdctx, inbuf, inlen)) {
    fprintf(stderr, "ERROR: EVP_DigestUpdate %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

// Digest 结束
int MY_Digest::Final(unsigned char *digest, int *digest_len) {
  if (1 != EVP_DigestFinal_ex(mdctx, digest, (unsigned int *)digest_len)) {
    fprintf(stderr, "ERROR: EVP_DigestFinal_ex %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

int MY_Digest::SignInit(const char *mname, EVP_PKEY *pkey) {
  md = (EVP_MD *)EVP_get_digestbyname(mname);
  if (!md) {
    fprintf(stderr, "ERROR: EVP_get_digestbyname: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  if (1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
    fprintf(stderr, "ERROR: EVP_DigestSignInit: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

int MY_Digest::SignUpdate(const unsigned char *inbuf, int inlen) {
  if (1 != EVP_DigestSignUpdate(mdctx, inbuf, inlen)) {
    fprintf(stderr, "ERROR: EVP_DigestSignUpdate: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

int MY_Digest::SignFinal(unsigned char *sig, size_t *sig_len) {
  if (1 != EVP_DigestSignFinal(mdctx, sig, sig_len)) {
    fprintf(stderr, "ERROR: EVP_DigestSignFinal: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  return 0;
}

/* bin转换为hex */
int bin2hex(unsigned char *dst, int *pd, unsigned char *src, int s) {
  *pd = s * 2;
  for (int i = 0; i < s; i++)
    sprintf((char *)dst + i * 2, "%02X", src[i]);
  return 0;
}

/* hex转换为bin */
int hex2bin(unsigned char *dst, int *pd, unsigned char *src, int s) {
  /* 16进制转换为二进制 */
  int u = 0;
  *pd = s / 2;
  for (int i = 0; i < s; i += 2) {
    sscanf((char *)src + i, "%02X", &u);
    dst[i / 2] = u;
  }
  return 0;
}
