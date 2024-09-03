// The following is a partial backport of crypto/dsa/dsa_lockl.h
// and crypto/dsa/dsa_lib.c, commit cbc8a839959418d8a2c2e3ec6bdf394852c9501e
// on the OpenSSL_1_1_0-stable branch. Only pqg and key getters/setters
// are backported.

#include "goopenssl.h"

struct dsa_st
{
    int _ignored0;
    long _ignored1;
    int _ignored2;
    GO_BIGNUM_PTR p;
    GO_BIGNUM_PTR q;
    GO_BIGNUM_PTR g;
    GO_BIGNUM_PTR pub_key;
    GO_BIGNUM_PTR priv_key;
    // The following members are not used by our backport,
    // so we don't define them here.
};

void go_openssl_DSA_get0_pqg_backport(const GO_DSA_PTR dsa,
                  GO_BIGNUM_PTR *p, GO_BIGNUM_PTR *q, GO_BIGNUM_PTR *g)
{
    const struct dsa_st *d = dsa;
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}

int go_openssl_DSA_set0_pqg_backport(GO_DSA_PTR dsa,
                  GO_BIGNUM_PTR p, GO_BIGNUM_PTR q, GO_BIGNUM_PTR g)
{
    struct dsa_st *d = dsa;
    if ((d->p == NULL && p == NULL)
        || (d->q == NULL && q == NULL)
        || (d->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        go_openssl_BN_free(d->p);
        d->p = p;
    }
    if (q != NULL) {
        go_openssl_BN_free(d->q);
        d->q = q;
    }
    if (g != NULL) {
        go_openssl_BN_free(d->g);
        d->g = g;
    }

    return 1;
}

void go_openssl_DSA_get0_key_backport(const GO_DSA_PTR dsa,
                  GO_BIGNUM_PTR *pub_key, GO_BIGNUM_PTR *priv_key)
{
    const struct dsa_st *d = dsa;
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}

int go_openssl_DSA_set0_key_backport(GO_DSA_PTR dsa, GO_BIGNUM_PTR pub_key, GO_BIGNUM_PTR priv_key)
{
    struct dsa_st *d = dsa;
    if (d->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        go_openssl_BN_free(d->pub_key);
        d->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        go_openssl_BN_free(d->priv_key);
        d->priv_key = priv_key;
    }

    return 1;
}