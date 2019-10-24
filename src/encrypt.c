#include "1A/encrypt.h"

/* 程序错误处理 */
void handleError(EVP_CIPHER_CTX *ctx, FILE *in, FILE *out) {
  if (!ctx)
    EVP_CIPHER_CTX_free(ctx);
  if (!in)
    fclose(in);
  if (!out)
    fclose(out);
  exit(1);
}

/* 对称加解密实现 */
int my_encrypt(int enc, const char *algorithm, const unsigned char *key,
               const unsigned char *iv, const char *input, const char *output,
               const char *format) {
  int inlen, outlen;
  unsigned char inbuf[1024] = {0}, outbuf[1024 + EVP_MAX_BLOCK_LENGTH] = {0};

  /* 打开文件 input 和 output */
  FILE *in = fopen(input, "r"), *out = fopen(output, "w");
  if (!(in || out)) {
    fprintf(stderr, "ERROR: fopen failed.\n");
    handleError(NULL, in, out);
  }

  /* 初始化 c 和 ctx */
  const EVP_CIPHER *c = EVP_get_cipherbyname(algorithm);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed.\n");
    handleError(ctx, in, out);
  }

  /* 检查 key 和 iv 的长度*/
  if (!EVP_CipherInit_ex(ctx, c, NULL, NULL, NULL, enc)) {
    fprintf(stderr, "EVP_CipherInit_ex failed.\n");
    handleError(ctx, in, out);
  }
  /* OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == */
  /*                (int)strlen((const char *)key)); */
  /* OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == */
  /*                (int)strlen((const char *)iv)); */

  /* 设置 key 和 iv */
  if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc))
    handleError(ctx, in, out);

  /* 对文件 in 进行加密, 结果存放在文件 out 中 */
  for (;;) {
    inlen = fread(inbuf, 1, 1024, in);
    if (inlen <= 0)
      /* EOF or ERROR */
      break;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
      handleError(ctx, in, out);
    /* TODO: 将二进制的数据转换为base64格式16进制的数据 */

    fwrite(outbuf, 1, outlen, out);
  }
  if (ferror(in))
    handleError(ctx, in, out);

  /* 文件 in 的剩余部分加密  */
  if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
    handleError(ctx, in, out);

  /* TODO: 将二进制的数据转换为base64格式16进制的数据 */

  fwrite(outbuf, 1, outlen, out);
  EVP_CIPHER_CTX_free(ctx);
  fclose(in);
  fclose(out);
  return 0;
}
