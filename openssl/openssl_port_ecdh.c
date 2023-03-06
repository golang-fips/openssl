// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goopenssl.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000

DEFINEFUNCINTERNAL(const char *, OBJ_nid2sn, (int n), (n))
DEFINEFUNCINTERNAL(OSSL_PARAM_BLD *, OSSL_PARAM_BLD_new, (void), ())
DEFINEFUNCINTERNAL(int, OSSL_PARAM_BLD_push_octet_string,
		   (OSSL_PARAM_BLD *bld, const char *key, const void *buf, size_t bsize),
		   (bld, key, buf, bsize))
DEFINEFUNCINTERNAL(int, OSSL_PARAM_BLD_push_utf8_string,
		   (OSSL_PARAM_BLD *bld, const char *key, const char *buf, size_t bsize),
		   (bld, key, buf, bsize))
DEFINEFUNCINTERNAL(OSSL_PARAM *, OSSL_PARAM_BLD_to_param, (OSSL_PARAM_BLD *bld), (bld))
DEFINEFUNCINTERNAL(void, OSSL_PARAM_BLD_free, (OSSL_PARAM_BLD *bld), (bld))
DEFINEFUNCINTERNAL(void, OSSL_PARAM_free, (OSSL_PARAM *params), (params))
DEFINEFUNCINTERNAL(int, OSSL_PARAM_BLD_push_BN,
		   (OSSL_PARAM_BLD *bld, const char *key, const BIGNUM *bn),
		   (bld, key, bn))
DEFINEFUNCINTERNAL(int, EVP_PKEY_fromdata_init, (GO_EVP_PKEY_CTX *ctx), (ctx))
DEFINEFUNCINTERNAL(int, EVP_PKEY_fromdata, (GO_EVP_PKEY_CTX *ctx, GO_EVP_PKEY **pkey, int selection, OSSL_PARAM params[]), (ctx, pkey, selection, params))

GO_EVP_PKEY *
_goboringcrypto_EVP_PKEY_new_for_ecdh(int nid, const uint8_t *bytes, size_t len, int is_private)
{
	OSSL_PARAM_BLD *bld;
	const char *group;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *result = NULL;
	int selection;

	bld = _goboringcrypto_internal_OSSL_PARAM_BLD_new();
	if (bld == NULL)
		return NULL;

	group = _goboringcrypto_internal_OBJ_nid2sn(nid);
	if (!_goboringcrypto_internal_OSSL_PARAM_BLD_push_utf8_string(bld, "group", group, strlen(group)))
		goto err;

	if (is_private) {
		BIGNUM *priv;

		priv = _goboringcrypto_BN_bin2bn(bytes, len, NULL);
		if (!priv)
			goto err;

		if (!_goboringcrypto_internal_OSSL_PARAM_BLD_push_BN(bld, "priv", priv))
			goto err;

		params = _goboringcrypto_internal_OSSL_PARAM_BLD_to_param(bld);
		_goboringcrypto_BN_free(priv);
		if (!params)
			goto err;

		selection = GO_EVP_PKEY_KEYPAIR;
	} else {
		if (!_goboringcrypto_internal_OSSL_PARAM_BLD_push_octet_string(bld, "pub", bytes, len))
			goto err;

		params = _goboringcrypto_internal_OSSL_PARAM_BLD_to_param(bld);
		if (!params)
			goto err;

		selection = GO_EVP_PKEY_PUBLIC_KEY;
	}

	ctx = _goboringcrypto_EVP_PKEY_CTX_new_id(GO_EVP_PKEY_EC, NULL);
	if (!ctx)
		goto err;

	if (_goboringcrypto_internal_EVP_PKEY_fromdata_init(ctx) != 1)
		goto err;

	if (_goboringcrypto_internal_EVP_PKEY_fromdata(ctx, &result, selection, &params[0]) != 1)
		goto err;

err:
	_goboringcrypto_internal_OSSL_PARAM_BLD_free(bld);
	_goboringcrypto_internal_OSSL_PARAM_free(params);
	_goboringcrypto_EVP_PKEY_CTX_free(ctx);
	return result;
}

#else

GO_EVP_PKEY *
_goboringcrypto_EVP_PKEY_new_for_ecdh(int nid, const uint8_t *bytes, size_t len, int is_private)
{
	EVP_PKEY *result = NULL;
	EC_KEY *key = NULL;

	key = _goboringcrypto_EC_KEY_new_by_curve_name(nid);
	if (!key)
		goto err;

	if (is_private) {
		BIGNUM *priv;

		priv = _goboringcrypto_BN_bin2bn(bytes, len, NULL);
		if (!priv)
			goto err;
		if (_goboringcrypto_EC_KEY_set_private_key(key, priv) != 1) {
			_goboringcrypto_BN_free(priv);
			goto err;
		}
		_goboringcrypto_BN_free(priv);
	} else {
		const EC_GROUP *group = _goboringcrypto_EC_KEY_get0_group(key);
		EC_POINT *pub;

		pub = _goboringcrypto_EC_POINT_new(group);
		if (!pub) {
			goto err;
		}
		if (_goboringcrypto_EC_POINT_oct2point(group, pub, bytes, len, NULL) != 1) {
			_goboringcrypto_EC_POINT_free(pub);
			goto err;
		}
		if (_goboringcrypto_EC_KEY_set_public_key(key, pub) != 1) {
			_goboringcrypto_EC_POINT_free(pub);
			goto err;
		}
		_goboringcrypto_EC_POINT_free(pub);
	}

	result = _goboringcrypto_EVP_PKEY_new();
	if (!result)
		goto err;

	if (_goboringcrypto_EVP_PKEY_assign_EC_KEY(result, key) != 1) {
		_goboringcrypto_EVP_PKEY_free(result);
		result = NULL;
		goto err;
	}
	key = NULL;

err:
	_goboringcrypto_EC_KEY_free(key);
	return result;
}

#endif
