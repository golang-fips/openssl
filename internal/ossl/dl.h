// This header file is used by the mkcgo tool to generate cgo and Go bindings for the
// OpenSSL C API. Run "go generate ." to regenerate the bindings.

#ifndef _GO_DL_SHIMS_H // only include this header once
#define _GO_DL_SHIMS_H

#include <stdlib.h> // size_t
#include <stdint.h> // uint64_t

void *dlopen(const char *path, int flags);
void *dlsym(void *handle, const char *symbol);
char *dlerror(void);

#endif // _GO_DL_SHIMS_H
