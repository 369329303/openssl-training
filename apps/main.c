#include "1A/digest.h"
#include "1A/encrypt.h"
#include "1A/my_hmac.h"

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
  char *mode = NULL, *algorithm = NULL, *key = NULL, *iv = NULL, *input = NULL,
       *output = NULL, *format = NULL;
  int ch;
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
      break;
    case 'k':
      key = optarg;
      break;
    case 'v':
      iv = optarg;
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
      exit(1);
    default:
      printf("unknow options!\n\n");
      show_help();
      exit(1);
    }
  }

  if (!format)
    format = "BINARY";

  if (!strncmp(mode, "digest", strlen("digest"))) {
    /* digest运算 */
    digest(algorithm, input, output, format);
  } else if (!strncmp(mode, "hmac", strlen("hmac"))) {
    /* hmac运算 */
    /* TODO: 函数定义有误,需重新实现 */
    my_hmac(algorithm, input, output, format);
  } else {
    /* 加解密运算 */
    int enc = !!strncmp(mode, "encrypt", strlen("encrypt"));
    my_encrypt(enc, algorithm, (const unsigned char *)key,
               (const unsigned char *)iv, input, output, format);
  }
  return 0;
}
