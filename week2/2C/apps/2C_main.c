#include "2C/create_csr.h"
#include <ctype.h>

/* 大写单词转小写 */
void upper_to_lower(char *str) {
  for (int i = 0; str[i]; i++)
    str[i] = tolower(str[i]);
}

/* 显示帮助信息 */
void show_help() {
  printf("Usage: 2B [options]...\n\n");
  printf("-d/--digest [SHA1|SHA256|SHA512]\n");
  printf("-k/--key                privatekey file\n");
  printf("-o/--output output file\n");
  printf("-f/--format [DER|PEM]\n");
  printf("-s/--subject            subject\n");
  printf("-h/--help               display this help\n");
  printf("\n");
}

/* 命令行参数定义 */
static struct option long_options[] = {{"digest", required_argument, 0, 'd'},
                                       {"key", required_argument, 0, 'k'},
                                       {"output", required_argument, 0, 'o'},
                                       {"format", required_argument, 0, 'f'},
                                       {"subject", required_argument, 0, 's'},
                                       {"help", no_argument, 0, 'h'},
                                       {0, 0, 0, 0}};

int main(int argc, char *argv[]) {
  /* 选项定义 */
  char *algorithm = "sha256", *keyfile = NULL, *output = NULL,
    *format = "PEM", *subject = NULL;
  int ch = 0;
  while (1) {
    ch = getopt_long_only(argc, argv, "d:k:o:f:s:h", long_options, NULL);
    if (ch == -1)
      break;
    switch (ch) {
    case 'd':
      algorithm = optarg;
      upper_to_lower(algorithm);
      break;
    case 'k':
      keyfile = optarg;
      break;
    case 'o':
      output = optarg;
      break;
    case 's':
      subject = optarg;
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

  create_csr(algorithm, keyfile, output, format, subject);
  return 0;
}
