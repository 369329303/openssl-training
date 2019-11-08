#include "1B/digest.hpp"
#include "1B/encrypt.hpp"
#include "1B/my_hmac.hpp"

#include <ctype.h>
#include <stdio.h>

/* 大写单词转小写 */
void upper_to_lower(char *str) {
  for (int i = 0; str[i]; i++)
    str[i] = tolower(str[i]);
}

/* 显示帮助信息 */
void show_help() {
  printf("Usage: 1A [options]...\n\n");
  printf("-m/--mode [encrypt|decrypt|digest|hmac]\n");
  printf("-a/--algorithm [RC4 | AES-128-CBC | AES-128-ECB | AES-256-CBC | "
         "AES-128-ECB | MD5 | SHA1 | SHA256]\n");
  printf("-k/--key HEX_STRING\n");
  printf("-v/--iv HEX_STRING\n");
  printf("-i/--input input_file\n");
  printf("-o/--output output_file\n");
  printf("-f/--format [BINARY|HEX|BASE64]\n");
  printf("-h/--help              display this help\n");
  printf("\n");
}

/* 命令行参数定义 */
static struct option long_options[] = {{"mode", required_argument, 0, 'm'},
                                       {"algorithm", required_argument, 0, 'a'},
                                       {"key", required_argument, 0, 'k'},
                                       {"iv", required_argument, 0, 'v'},
                                       {"input", required_argument, 0, 'i'},
                                       {"output", required_argument, 0, 'o'},
                                       {"format", required_argument, 0, 'f'},
                                       {"help", no_argument, 0, 'h'},
                                       {0, 0, 0, 0}};

int main(int argc, char *argv[]) {
  /* 选项定义 */
  char *mode = NULL, *algorithm = NULL, *input = NULL, *output = NULL,
       *format = NULL;
  unsigned char *key = NULL, *iv = NULL, *nbuf = NULL;
  int ch = 0, len = 0, nlen = 0;

  format = (char *)"BINARY";
  nbuf = (unsigned char *)malloc(BUFSIZE);
  while (1) {
    ch = getopt_long(argc, argv, "m:a:k:v:i:o:f:h", long_options, NULL);
    if (ch == -1)
      break;
    switch (ch) {
    case 'm':
      mode = optarg;
      break;
    case 'a':
      algorithm = optarg;
      upper_to_lower(algorithm);
      break;
    case 'k':
      key = (unsigned char *)optarg;
      len = strlen((char *)key);
      hex2bin(nbuf, &nlen, key, len);
      memcpy(key, nbuf, nlen);
      break;
    case 'v':
      iv = (unsigned char *)optarg;
      len = strlen((char *)iv);
      hex2bin(nbuf, &nlen, iv, len);
      memcpy(iv, nbuf, nlen);
      break;
    case 'i':
      input = optarg;
      break;
    case 'o':
      output = optarg;
      break;
    case 'f':
      format = optarg;
      break;
    case 'h':
      show_help();
      exit(0);
    default:
      printf("unknow options!\n\n");
      show_help();
      exit(1);
    }
  }

  if (!strncmp(mode, "digest", strlen("digest"))) {
    /* digest运算 */
    digest(algorithm, input, output, format);
  } else if (!strncmp(mode, "hmac", strlen("hmac"))) {
    /* hmac运算 */
    my_hmac(algorithm, key, nlen, input, output, format);
  } else {
    /* 加解密运算 */
    int enc = strncmp(mode, "encrypt", strlen("encrypt")) ? 0 : 1;
    my_encrypt(enc, algorithm, key, iv, input, output, format);
  }

  free(nbuf);
  return 0;
}
