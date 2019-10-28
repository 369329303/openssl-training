#include "1A/encrypt.h"
#include "1A/helper.h"

/* 程序错误处理,释放内存,关闭文件 */
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
int my_encrypt(int enc, const char *algorithm, unsigned char *key,
               unsigned char *iv, const char *infile, const char *outfile,
               const char *format) {
  int inlen = 0, outlen = 0;
  unsigned char inbuf[BUFSIZE] = {0},
                outbuf[BUFSIZE + EVP_MAX_BLOCK_LENGTH] = {0};
  unsigned char *nbuf = (unsigned char *)malloc(BUFSIZE * 2);
  int nlen = 0;

  /* 打开文件 input 和 output */
  FILE *in = fopen(infile, "rb"), *out = fopen(outfile, "wb");
  if (!(in || out)) {
    fprintf(stderr, "ERROR: fopen: %s\n", strerror(errno));
    handleError(NULL, in, out);
  }

  /* 初始化 c 和 ctx, b64_en_ctx, b64_de_ctx */
  const EVP_CIPHER *c = EVP_get_cipherbyname(algorithm);
  if (!c) {
    fprintf(stderr, "ERROR: EVP_get_cipherbyname: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    handleError(NULL, in, out);
  }
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    handleError(ctx, in, out);
  }
  EVP_ENCODE_CTX *b64_ctx = EVP_ENCODE_CTX_new();
  if (!b64_ctx) {
    fprintf(stderr, "ERROR: EVP_ENCODE_CTX_new: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    handleError(ctx, in, out);
  }

  /* 初始化ctx */
  if (!EVP_CipherInit_ex(ctx, c, NULL, NULL, NULL, enc)) {
    fprintf(stderr, "ERROR: EVP_CipherInit_ex: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    handleError(ctx, in, out);
  }

  /* 向ctx中加入 key 和 iv */
  if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc)) {
    fprintf(stderr, "ERROR: EVP_CipherInit_ex: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    handleError(ctx, in, out);
  }

  /* 初始化b64_ctx, 加密后编码,解密前编码 */
  /* 1 --- 加密 */
  /* 0 --- 解密 */
  1 == enc ? EVP_EncodeInit(b64_ctx) : EVP_DecodeInit(b64_ctx);

  /* 对文件内容进行加/解密 */
  for (;;) {
    inlen = fread(inbuf, 1, BUFSIZE, in);
    /* 文件读取结束 */
    if (inlen <= 0)
      break;
    /* 如果是解密,需转换为二进制数据 */
    if (0 == enc) {
      if (0 == strncmp(format, "BASE64", 6)) {
        /* 这个函数的返回值比较特殊,0和1都标识正常, */
        /* 0 --- 遇到了 "=" 符号 */
        /* 1 --- 未遇到 "=" 符号 */
        if (-1 == EVP_DecodeUpdate(b64_ctx, nbuf, &nlen, inbuf, inlen)) {
          fprintf(stderr, "ERROR: EVP_DecodeUpdate: %s\n",
                  ERR_error_string(ERR_get_error(), NULL));
          handleError(ctx, in, out);
        }
        memcpy(inbuf, nbuf, nlen);
        inlen = nlen;
        if (inlen < BUFSIZE) {
          /* 最后一次读取到文件内容 */
          EVP_DecodeFinal(b64_ctx, nbuf, &nlen);
          memcpy(inbuf + inlen, nbuf, nlen);
          inlen += nlen;
        }        
      } else if (0 == strncmp(format, "HEX", 3)) {
        hex2bin(nbuf, &nlen, inbuf, inlen);
        memcpy(inbuf, nbuf, nlen);
        inlen = nlen;
      } else if (0 != strncmp(format, "BINARY", 6)) {
        fprintf(stderr, "ERROR: WRONG FORMAT!");
      }
    }

    /* 加/解密文件 */
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
      fprintf(stderr, "ERROR: EVP_CipherUpdate: %s",
              ERR_error_string(ERR_get_error(), NULL));
      handleError(ctx, in, out);
    }
    /* 如果是加密,需要转换成对应的编码格式保存 */
    if (1 == enc) {
      if (0 == strncmp(format, "BASE64", 6)) {
        if (!EVP_EncodeUpdate(b64_ctx, nbuf, &nlen, outbuf, outlen)) {
          fprintf(stderr, "ERROR: EVP_EncodeUpdate: %s\n",
                  ERR_error_string(ERR_get_error(), NULL));
          handleError(ctx, in, out);
        }
        memcpy(outbuf, nbuf, nlen);
        outlen = nlen;
      } else if (0 == strncmp(format, "HEX", 3)) {
        bin2hex(nbuf, &nlen, outbuf, outlen);
        memcpy(outbuf, nbuf, nlen);
        outlen = nlen;
      } else if (0 != strncmp(format, "BINARY", 6)) {
        fprintf(stderr, "ERROR: WRONG FORMAT!");
      }
    }
    fwrite(outbuf, 1, outlen, out);
  }

  /* 检查读取文件时是否遇到错误 */
  if (ferror(in)) {
    fprintf(stderr, "ERROR: ferror: %s\n", strerror(errno));
    handleError(ctx, in, out);
  }

  /* 文件 in 的最后一块数据加/解密  */
  if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
    fprintf(stderr, "ERROR: EVP_CipherFinal_ex %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    handleError(ctx, in, out);
  }
  /* 如果是加密,需要转换成对应的编码格式 */
  if (1 == enc) {
    if (0 == strncmp(format, "BASE64", 6)) {
      /* CipherFinal之后仍然要EncodeUpdate,从而对所有的加密数据进行编码 */
      EVP_EncodeUpdate(b64_ctx, nbuf, &nlen, outbuf, outlen);
      fwrite(nbuf, nlen, outlen, out);
      EVP_EncodeFinal(b64_ctx, outbuf, &outlen);
    } else if (0 == strncmp(format, "HEX", 3)) {
      bin2hex(nbuf, &nlen, outbuf, outlen);
      outlen = nlen;
      memcpy(outbuf, nbuf, outlen);
    } else if (0 != strncmp(format, "BINARY", 6)) {
      fprintf(stderr, "ERROR: WRONG FORMAT!");
    }
  }
  fwrite(outbuf, 1, outlen, out);

  /* 释放内存,关闭文件 */
  free(nbuf);
  EVP_CIPHER_CTX_free(ctx);
  fclose(in);
  fclose(out);
  return 0;
}
