//go:build linux && !android
// +build linux,!android

package openssl_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"github.com/golang-fips/openssl-fips/openssl"
	"github.com/golang-fips/openssl-fips/openssl/bbig"
	"math/big"
	"testing"
)

func fromBase16(base16 string) openssl.BigInt {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		panic("bad number: " + base16)
	}
	return bbig.Enc(i)
}

type PrivateKey struct {
	N    openssl.BigInt
	E    openssl.BigInt
	D    openssl.BigInt
	P    openssl.BigInt
	Q    openssl.BigInt
	Dp   openssl.BigInt
	Dq   openssl.BigInt
	Qinv openssl.BigInt
}

// This is taken from the following key:
//
// -----BEGIN RSA TESTING KEY-----
// MIIEogIBAAKCAQEAp5qgUIj096pw8U+AjcJucLWenR3oe+tEthXiAuqcYgslW5UU
// lMim34U/h7NbLvbG2KJ2chUsmLtuCFaoIe/YKW5DKm3SPytK/KCBsVa+MQ7zuF/1
// ks5p7yBqFBl6QTekMzwskt/zyDIG9f3A+38akruHNBvUgYqwbWPx4ycclQ52GSev
// /Cfx0I68TGT5SwN/eCJ/ghq3iGAf0mX1bkVaW1seKbL49aAA94KnDCRdl813+S2R
// EPDf2tZwlT0JpZm5QtAqthonZjkjHocZNxhkKF3XWUntE/+l6R4A+CWZlC2vmUc1
// hJTEraksy2JUIjxAaq//FnDpIEVG/N2ofmNpaQIDAQABAoIBAAYH7h9fwkLcNvqz
// 8+oF9k/ndSjtr9UvstYDhRG6S/zKLmK0g1xUOQ7/fjj9lvkiZ6bZd74krWlkizHR
// HnU0KnjZLyEKeR+NSQI8q1YMi0T8JwB6MX3CIDU62x5UiV3p6OZwEqGJXf4U8MOu
// ySAzo2rmxRd2reeobC9Pgp98I47oeqaSRwFVZRPfKk5RvfI7KRmL58BAB0XS56PA
// PJ+3l0fB/oIV11iaBEKildxLDtrvlepQ2KPNf7Dpk0/CPRtS/jxyxIyML8tjR3F0
// KuHplsRjTANyzW/aHddO1fnfnXsVo+0PzSPTHCbxKSu5XmChqsKoB1jM+/tJci4y
// ST5hUXUCgYEAzfA5XEMkR/NNJMfR+FBbdfpQ1b0wqH3qtWZx/tBjKC2Y0XnDQ8ZR
// SEWONLVZMRtTlJaHIPZ9i6anQRR5harrff0OpsKiJUGDout8ehE6eiN8ABWGNlCI
// AiLCerVJZMDcSuDU7xsdHVIdSxYh88Z9g54vUQ4214BG/G0Qm1emV3UCgYEA0FjP
// wq5cEGt9xDCg+oXk0bLm4Wn4FkabJH7M+oCosHHY9W1vgvv50bpNoAbaB5r1mlan
// T6gEtkQPB2juMTnuIwRL+kvOmSKqZGlAsyrq8smTuBUv7brbybkYN3Rg51KV6u1J
// vCdGpMYWHUNRkkQ88cr6iFPodYU+CzRR4ABif6UCgYBc0jDYb/7TW0tjD5mJJZcD
// xw5WOE7NMuvuVT1+T6jRvDOL/yjOzH1oaMle4npQEvQKHgrMBa2ymyv5vmPDprU7
// 9Sp8aW+yASR281MIpelIkePbGdiDdKrI46fqrPlmqzLfoRT4rKzjwVYouNIW0VlT
// UKIdE54OZegY8IOysL/t3QKBgDZnSnECiIW9G80UCaUBO3vKZGFuA1sFutMvzSSI
// XgQc5lNH7TtdwqESLdzgjSQ5QXK4t92j+P8DDI2Zx8DQ6K76G0DTdLImDCpGFZ/z
// UABvxIPn/GjuRyAIlhs852Tf+seqiHt6Igc6tmGTx4QTD3rvzrW0e1ncnhPc6Jg+
// YXoFAoGARD9OPrd4J2N+nkSWif9VOuPHvOXEczwBDJbsAGrOW1kTbDStF0OIVOt0
// Ukj+mnnL8ZNyVLgTrZDRfXvlA94EbPK5/rMAYwjMlXHP8R22ts3eDMNUdw0/Zl1g
// QOhL8wXZcdwHKsONy55kZHo8pmneqi9EnqqLGguLwx5WIMzWvZ8=
// -----END RSA TESTING KEY-----
//
// After changing "TESTING" to "PRIVATE", do:
//
//	openssl pkey -in key.pem -text
var privateKey = &PrivateKey{
	N:    fromBase16("00a79aa05088f4f7aa70f14f808dc26e70b59e9d1de87beb44b615e202ea9c620b255b951494c8a6df853f87b35b2ef6c6d8a27672152c98bb6e0856a821efd8296e432a6dd23f2b4afca081b156be310ef3b85ff592ce69ef206a14197a4137a4333c2c92dff3c83206f5fdc0fb7f1a92bb87341bd4818ab06d63f1e3271c950e761927affc27f1d08ebc4c64f94b037f78227f821ab788601fd265f56e455a5b5b1e29b2f8f5a000f782a70c245d97cd77f92d9110f0dfdad670953d09a599b942d02ab61a276639231e8719371864285dd75949ed13ffa5e91e00f82599942daf9947358494c4ada92ccb6254223c406aafff1670e9204546fcdda87e636969"),
	E:    fromBase16("10001"),
	D:    fromBase16("0607ee1f5fc242dc36fab3f3ea05f64fe77528edafd52fb2d6038511ba4bfcca2e62b4835c54390eff7e38fd96f92267a6d977be24ad69648b31d11e75342a78d92f210a791f8d49023cab560c8b44fc27007a317dc220353adb1e54895de9e8e67012a1895dfe14f0c3aec92033a36ae6c51776ade7a86c2f4f829f7c238ee87aa6924701556513df2a4e51bdf23b29198be7c0400745d2e7a3c03c9fb79747c1fe8215d7589a0442a295dc4b0edaef95ea50d8a3cd7fb0e9934fc23d1b52fe3c72c48c8c2fcb634771742ae1e996c4634c0372cd6fda1dd74ed5f9df9d7b15a3ed0fcd23d31c26f1292bb95e60a1aac2a80758ccfbfb49722e32493e615175"),
	P:    fromBase16("00cdf0395c432447f34d24c7d1f8505b75fa50d5bd30a87deab56671fed063282d98d179c343c65148458e34b559311b5394968720f67d8ba6a741147985aaeb7dfd0ea6c2a2254183a2eb7c7a113a7a237c0015863650880222c27ab54964c0dc4ae0d4ef1b1d1d521d4b1621f3c67d839e2f510e36d78046fc6d109b57a65775"),
	Q:    fromBase16("00d058cfc2ae5c106b7dc430a0fa85e4d1b2e6e169f816469b247eccfa80a8b071d8f56d6f82fbf9d1ba4da006da079af59a56a74fa804b6440f0768ee3139ee23044bfa4bce9922aa646940b32aeaf2c993b8152fedbadbc9b918377460e75295eaed49bc2746a4c6161d435192443cf1cafa8853e875853e0b3451e000627fa5"),
	Dp:   fromBase16("5cd230d86ffed35b4b630f9989259703c70e56384ecd32ebee553d7e4fa8d1bc338bff28cecc7d6868c95ee27a5012f40a1e0acc05adb29b2bf9be63c3a6b53bf52a7c696fb2012476f35308a5e94891e3db19d88374aac8e3a7eaacf966ab32dfa114f8acace3c15628b8d216d1595350a21d139e0e65e818f083b2b0bfeddd"),
	Dq:   fromBase16("36674a71028885bd1bcd1409a5013b7bca64616e035b05bad32fcd24885e041ce65347ed3b5dc2a1122ddce08d24394172b8b7dda3f8ff030c8d99c7c0d0e8aefa1b40d374b2260c2a46159ff350006fc483e7fc68ee472008961b3ce764dffac7aa887b7a22073ab66193c784130f7aefceb5b47b59dc9e13dce8983e617a05"),
	Qinv: fromBase16("443f4e3eb77827637e9e449689ff553ae3c7bce5c4733c010c96ec006ace5b59136c34ad17438854eb745248fe9a79cbf1937254b813ad90d17d7be503de046cf2b9feb3006308cc9571cff11db6b6cdde0cc354770d3f665d6040e84bf305d971dc072ac38dcb9e64647a3ca669deaa2f449eaa8b1a0b8bc31e5620ccd6bd9f"),
}

// These vectors have been tested with
//
//	`openssl rsautl -verify -inkey pk -in signature | hexdump -C`
var signPKCS1v15Tests = []struct {
	in  string
	out string
	h   crypto.Hash
}{
	{"Test.\n", "0c7da2fe34372c9e433ca668b6edf4cd7f7eb29f11c11c44d99cb6dc6fe4344cc656075015de6d0249d25b6e01bf22276e9f97f6e64f5905ce96cfc69e3c30e3813eb80553b1e53993482b97c920d030e1daf6c5f11f532a166a4b4aea34c6f8ed5579ccf6bfd5e20250d1979e97c358363da8ae15a095f07e9c54bfb948a94a75a6c8a0cbe4b9970d780ddf49369b2f134915e9a8ccf20e7b07981d0b95978630ee754f20bad163cdcff8c56c9bc66fd1060961779f1554894597086477d15346955d1a1c67d9718c4d25d840cf83fe203fd4e5681fc388a0395b79b94b1ade281f3682fb08a02ed6fa209caf489e9ccf501a86e99a36737b241c1e8ab2c2a4", crypto.SHA256},
}

func TestPKCS1v15(t *testing.T) {
	pub, err := openssl.NewPublicKeyRSA(
		privateKey.N,
		privateKey.E,
	)
	if err != nil {
		t.Errorf("error in openssl.NewPublicKeyRSA: %s", err)
	}

	priv, err := openssl.NewPrivateKeyRSA(
		privateKey.N,
		privateKey.E,
		privateKey.D,
		privateKey.P,
		privateKey.Q,
		privateKey.Dp,
		privateKey.Dq,
		privateKey.Qinv,
	)
	if err != nil {
		t.Errorf("error in openssl.NewPrivateKeyRSA: %s", err)
	}

	for i, test := range signPKCS1v15Tests {
		for _, msgIsHashed := range []bool{true, false} {
			var msg []byte
			if msgIsHashed {
				h := test.h.New()
				h.Write([]byte(test.in))
				msg = h.Sum(nil)
			} else {
				msg = make([]byte, len(test.in))
				copy(msg, []byte(test.in))
			}

			s, err := openssl.SignRSAPKCS1v15(priv, test.h, msg, msgIsHashed)
			if err != nil {
				t.Errorf("#%d %s", i, err)
			}

			expected, _ := hex.DecodeString(test.out)
			if !bytes.Equal(s, expected) {
				t.Errorf("#%d got: %x want: %x", i, s, expected)
			}

			err = openssl.VerifyRSAPKCS1v15(pub, test.h, msg, s, msgIsHashed)
			if err != nil {
				t.Errorf("#%d %s", i, err)
			}
		}
	}
}
