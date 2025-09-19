#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#include <openssl/sha.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

#define MAX_FILE_READ (400 * 1024 * 1024)
#define MIN_STRING_LEN 4
#define SLIDE_WINDOW 4096
#define SLIDE_STEP 512

static const char *packer_sigs[] = {
        "UPX", "MPRESS", "THEMIDA", "ASPACK", "ASPACK", "mpress", NULL
};

static unsigned char *read_file(const char *path, size_t *out_size) {

}
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                                                                                                                                                                                     
~                              
