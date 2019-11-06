#include "3A/evp_open.h"
#include "3A/evp_seal.h"
#include <ctype.h>

/* 大写单词转小写 */
void upper_to_lower(char *str) {
  for (int i = 0; str[i]; i++)
    str[i] = tolower(str[i]);
}

/* 显示帮助信息 */
void show_help() {
  printf("Usage: 3A [options]...\n\n");
  printf("-e/--encrypt \n");
  printf("-d/--decrpt  \n");
  printf("-k/--key     pkey file\n");
  printf("-i/--input   input file\n");
  printf("-o/--output  output file\n");
  printf("-h/--help    display this help\n");
  printf("\n");
}

/* 命令行参数定义 */
static struct option long_options[] = {{"encrypt", required_argument, 0, 'e'},
                                       {"decrypt", required_argument, 0, 'd'},
                                       {"key", required_argument, 0, 'k'},
                                       {"input", required_argument, 0, 'i'},
                                       {"output", required_argument, 0, 'o'},
                                       {"help", no_argument, 0, 'h'},
                                       {0, 0, 0, 0}};

int main(int argc, char *argv[]) {
  /* 选项定义 */
  int mode = 1;
  char *keyfile = NULL, *infile = NULL, *outfile = NULL;
  int ch = 0;
  while (1) {
    ch = getopt_long_only(argc, argv, "edk:i:o:h", long_options, NULL);
    if (ch == -1)
      break;
    switch (ch) {
    case 'e':
      mode = EVP_SEAL;
      break;
    case 'd':
      mode = EVP_OPEN;
      break;
    case 'k':
      keyfile = optarg;
      break;
    case 'i':
      infile = optarg;
      break;
    case 'o':
      outfile = optarg;
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

  mode ? evp_seal(keyfile, infile, outfile)
       : evp_open(keyfile, infile, outfile);
  return 0;
}
