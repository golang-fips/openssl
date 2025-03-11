#ifndef GO_OSSL_ERROR_H // only include this header once
#define GO_OSSL_ERROR_H

#include <shims.h>
#include <stdlib.h> // for free()
#include <string.h> // for strdup()

int OPENSSL_version_major_Available();

// OpenSSL only allows a maximum of 16 errors to be stored in the error queue.
#define ERR_NUM_MAX  16

// mkcgo_err_state is a custom structure to hold the error state
// of OpenSSL.
typedef struct mkcgo_err_state_st {
	unsigned long code[ERR_NUM_MAX];
	int line[ERR_NUM_MAX];
	char *file[ERR_NUM_MAX];
} mkcgo_err_state;

// mkcgo_err_clear clears the error queue in OpenSSL.
static void mkcgo_err_clear() {
	// Clear the error queue.
	ERR_clear_error();
}

// mkcgo_err_retrieve retrieves the error state from OpenSSL.
// It returns a pointer to a mkcgo_err_state structure
// that contains the error codes, lines, and file names.
// The caller is responsible for freeing the memory
// by calling mkcgo_err_free.
static mkcgo_err_state *mkcgo_err_retrieve() {
	mkcgo_err_state *errs = (mkcgo_err_state *)malloc(sizeof(mkcgo_err_state));
	if (errs == NULL) {
		return NULL;
	}
	// Initialize the error state to zero.
	for (int i = 0; i < ERR_NUM_MAX; i++) {
		errs->code[i] = 0;
		errs->line[i] = 0;
		errs->file[i] = NULL;
	}
	// Retrieve the errors from OpenSSL.
	for (int i = 0; i < ERR_NUM_MAX; i++) {
		const char *file;
		if (OPENSSL_version_major_Available() == 1) { // Only available in OpenSSL 3.
			// OpenSSL 3 error handling
			errs->code[i] = ERR_get_error_all(&file, &errs->line[i], NULL, NULL, NULL);
		} else {
			// OpenSSL 1 error handling
			errs->code[i] = ERR_get_error_line(&file, &errs->line[i]);
		}
		if (errs->code[i] == 0) {
			break;
		}
		if (file != NULL) {
			// Copy the file name as the pointer we just retrieved will by OpenSSL
			// when the error queue is cleared.
			errs->file[i] = strdup(file);
		}
	}
	return errs;
}

static void mkcgo_err_free(mkcgo_err_state *errs) {
	if (errs == NULL) {
		return;
	}
	for (int i = 0; i < ERR_NUM_MAX; i++) {
		if (errs->file[i] != NULL) {
			free((void *)errs->file[i]);
		}
	}
	free(errs);
}

#endif // GO_OSSL_ERROR_H