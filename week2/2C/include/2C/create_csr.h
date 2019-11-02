#include "2C/2C_main.h"

#define DER 0
#define PEM 1

int create_csr(const char *algorithm, const char *keyfile, const char *outfile,
               const char *format, char *subject);
