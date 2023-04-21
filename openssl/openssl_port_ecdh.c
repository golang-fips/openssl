// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

#include "goopenssl.h"

static GO_EC_POINT *
public_key_from_private(const GO_EC_GROUP *group, const GO_BIGNUM *priv)
{
	// OpenSSL does not expose any method to generate the public
	// key from the private key [1], so we have to calculate it here.
	// [1] https://github.com/openssl/openssl/issues/18437#issuecomment-1144717206
	GO_EC_POINT *point;

	point = _goboringcrypto_EC_POINT_new(group);
	if (!point)
		return NULL;

	if (_goboringcrypto_EC_POINT_mul(group, point, priv, NULL, NULL, NULL) != 1) {
		_goboringcrypto_EC_POINT_free(point);
		return NULL;
	}

	return point;
}

static size_t
encode_point(const GO_EC_GROUP *group, const GO_EC_POINT *point,
	     unsigned char **result)
{
	size_t len;

	len = _goboringcrypto_EC_POINT_point2oct(group, point,
						 GO_POINT_CONVERSION_UNCOMPRESSED,
						 NULL, 0, NULL);
	if (!len)
		return 0;

	*result = malloc(len);
	if (!*result)
		return 0;

	len = _goboringcrypto_EC_POINT_point2oct(group, point,
						 GO_POINT_CONVERSION_UNCOMPRESSED,
						 *result, len, NULL);
	if (!len) {
		free(*result);
		return 0;
	}

	return len;
}

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
	const char *group_name;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *result = NULL;
	int selection;

	/* EVP_PKEY_fromdata in earlier 3.0 releases does not check
	 * that the given point is on the curve.  We do that manually
	 * with EC_POINT_oct2point.
	 */
	if (!is_private) {
		EC_GROUP *group;
		EC_POINT *point;
		int ok;

		group = _goboringcrypto_EC_GROUP_new_by_curve_name(nid);
		if (!group)
			return NULL;

		point = _goboringcrypto_EC_POINT_new(group);
		if (!point) {
			_goboringcrypto_EC_GROUP_free(group);
			return NULL;
		}

		ok = _goboringcrypto_EC_POINT_oct2point(group, point, bytes, len, NULL);

		_goboringcrypto_EC_POINT_free(point);
		_goboringcrypto_EC_GROUP_free(group);

		if (!ok)
			return NULL;
	}

	bld = _goboringcrypto_internal_OSSL_PARAM_BLD_new();
	if (bld == NULL)
		return NULL;

	group_name = _goboringcrypto_internal_OBJ_nid2sn(nid);
	if (!_goboringcrypto_internal_OSSL_PARAM_BLD_push_utf8_string(bld, "group", group_name, strlen(group_name)))
		goto err;

	if (is_private) {
		BIGNUM *priv;

		priv = _goboringcrypto_BN_bin2bn(bytes, len, NULL);
		if (!priv)
			goto err;

		if (!_goboringcrypto_internal_OSSL_PARAM_BLD_push_BN(bld, "priv", priv)) {
			_goboringcrypto_BN_clear_free(priv);
			goto err;
		}

		params = _goboringcrypto_internal_OSSL_PARAM_BLD_to_param(bld);
		if (!params) {
			_goboringcrypto_BN_clear_free(priv);
			goto err;
		}

		_goboringcrypto_BN_clear_free(priv);
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

DEFINEFUNCINTERNAL(void, CRYPTO_free, (void *addr, const char *file, int line), (addr, file, line))

size_t
_goboringcrypto_EVP_PKEY_get1_encoded_ecdh_public_key(GO_EVP_PKEY *pkey,
						      unsigned char **result)
{
	unsigned char *res;
	size_t len;

	len = _goboringcrypto_EVP_PKEY_get1_encoded_public_key(pkey, &res);
	if (!len)
		return 0;

	*result = malloc(len);
	if (!*result) {
		_goboringcrypto_internal_CRYPTO_free(res, __FILE__, __LINE__);
		return 0;
	}
	memcpy(*result, res, len);
	_goboringcrypto_internal_CRYPTO_free(res, __FILE__, __LINE__);
	return len;
}

int
_goboringcrypto_EVP_PKEY_set_ecdh_public_key_from_private(GO_EVP_PKEY *pkey, int nid)
{
	GO_BIGNUM *priv = NULL;
	GO_EC_GROUP *group = NULL;
	GO_EC_POINT *point = NULL;
	size_t len;
	unsigned char *pub = NULL;
	int result = 0;

	if (_goboringcrypto_EVP_PKEY_get_bn_param(pkey, "priv", &priv) != 1)
		return 0;

	group = _goboringcrypto_EC_GROUP_new_by_curve_name(nid);
	if (!group)
		goto err;

	point = public_key_from_private(group, priv);
	if (!point)
		goto err;

	len = encode_point(group, point, &pub);
	if (!len)
		goto err;

	if (_goboringcrypto_EVP_PKEY_set1_encoded_public_key(pkey, pub, len) != 1)
		goto err;

	result = 1;

err:
	_goboringcrypto_EC_GROUP_free(group);
	_goboringcrypto_EC_POINT_free(point);
	_goboringcrypto_BN_free(priv);
	free(pub);
	return result;
}

#else

GO_EVP_PKEY *
_goboringcrypto_EVP_PKEY_new_for_ecdh(int nid, const uint8_t *bytes, size_t len, int is_private)
{
	GO_EVP_PKEY *result = NULL;
	GO_EC_KEY *key = NULL;

	key = _goboringcrypto_EC_KEY_new_by_curve_name(nid);
	if (!key)
		goto err;

	if (is_private) {
		BIGNUM *priv;

		priv = _goboringcrypto_BN_bin2bn(bytes, len, NULL);
		if (!priv)
			goto err;
		if (_goboringcrypto_EC_KEY_set_private_key(key, priv) != 1) {
			_goboringcrypto_BN_clear_free(priv);
			goto err;
		}
		_goboringcrypto_BN_clear_free(priv);
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

size_t
_goboringcrypto_EVP_PKEY_get1_encoded_ecdh_public_key(GO_EVP_PKEY *pkey,
						      unsigned char **result)
{
	const GO_EC_KEY *key;
	const GO_EC_POINT *point;
	const GO_EC_GROUP *group;
	size_t len;

	key = _goboringcrypto_EVP_PKEY_get0_EC_KEY(pkey);
	if (!key)
		return 0;

	point = _goboringcrypto_EC_KEY_get0_public_key(key);
	if (!point)
		return 0;

	group = _goboringcrypto_EC_KEY_get0_group(key);
	if (!group)
		return 0;

	return encode_point(group, point, result);
}

int
_goboringcrypto_EVP_PKEY_set_ecdh_public_key_from_private(GO_EVP_PKEY *pkey, int nid)
{
	GO_EC_KEY *key;
	const GO_BIGNUM *priv;
	const GO_EC_GROUP *group;
	GO_EC_POINT *point;

	key = (GO_EC_KEY *)_goboringcrypto_EVP_PKEY_get0_EC_KEY(pkey);
	if (!key)
		return 0;

	priv = _goboringcrypto_EC_KEY_get0_private_key(key);
	if (!priv)
		return 0;

	group = _goboringcrypto_EC_KEY_get0_group(key);
	point = public_key_from_private(group, priv);
	if (!point)
		return 0;

	if (_goboringcrypto_EC_KEY_set_public_key(key, point) != 1) {
		_goboringcrypto_EC_POINT_free(point);
		return 0;
	}

	_goboringcrypto_EC_POINT_free(point);
	return 1;
}

#endif
