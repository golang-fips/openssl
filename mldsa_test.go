package openssl_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/golang-fips/openssl/v2"
)

type mldsaTestCase struct {
	name string
	seed string
	msg  string
}

type mldsaExternalMuTestCase struct {
	name   string
	params openssl.MLDSAParameters
	seed   string
	mu     string
}

var mldsaParameterTests = []struct {
	name   string
	params openssl.MLDSAParameters
}{
	{"44", openssl.MLDSA44()},
	{"65", openssl.MLDSA65()},
	{"87", openssl.MLDSA87()},
}

var mldsaACVPTestCases = []mldsaTestCase{
	// From crypto/internal/fips140/mldsa/mldsa_test.go TestACVPRejectionKATs.
	{"Path/ML-DSA-44/1", "5C624FCC1862452452D0C665840D8237F43108E5499EDCDC108FBC49D596E4B7", "951FDF5473A4CBA6D9E5B5DB7E79FB8173921BA5B13E9271401B8F907B8B7D5B"},
	{"Path/ML-DSA-44/2", "836EABEDB4D2CD9BE6A4D957CF5EE6BF489304136864C55C2C5F01DA5047D18B", "199A0AB735E9004163DD02D319A61CFE81638E3BF47BB1E90E90D6E3EA545247"},
	{"Path/ML-DSA-44/3", "CA5A01E1EA6552CB5C9803462B94C2F1DC9D13BB17A6ACE510D157056A2C6114", "8C8CACA88FFF52B9330510537B3701B3993F3726136A650F48F8604551550832"},
	{"Path/ML-DSA-44/4", "9C005F1550B4F31855C6B92F978736733F37791CB39DD182D7BA5732BDC2483E", "B744343F30F7FEE088998BA574E799F1BF3939C06C29BF9AC10F3588A57E21E2"},
	{"Path/ML-DSA-44/5", "4FAB5485B009399E8AE6FC3D3EEFBFE8E09796E4477AABD5EB1CC908FA734DE3", "7CAB0FDCF4BEA5F039137478AA45C9C48EF96D906FC49F6E2F138111BF1B4A4E"},
	{"Path/ML-DSA-65/1", "464756A985E5DF03739D95DD309C1ED9C5B04254CC294E7E7EB9B9365EE15117", "491101BBA044DE6E44A63796C33CDA051BB05A60725B87AF4BA9DB940C03AC09"},
	{"Path/ML-DSA-65/2", "235A48DB4CA7916B884F424A8586EFD517E87C64AECEC0FCE9A3CC212BA1522E", "F8CE85CB2EC474FFBF5A3FFAE029CE6F4526B8D597655067F97F438B81071E9B"},
	{"Path/ML-DSA-65/3", "E13131B705A760305FEFFEBFE99082E2691A444BBEFCC3EDF67D909886200207", "CD365512C7E61BBAA130800B37F3BB46AAF1BEEF3742EA8A9010A6DD4576ED0B"},
	{"Path/ML-DSA-65/4", "0A4793E040A4BC0D0F37643D12C1EA1F10648724609936C76E0EC83E37209E92", "6D9C7A795E48D80A892CBF4D4558429787277E3806EB5D0BCE1640EEBBBF9AEC"},
	{"Path/ML-DSA-65/5", "F865B889E5022D54BABC81CA67E7EB39F1AC42F92CF5295C3DA5C9667DB1B924", "047AFAADBE020ED2D766DA85317DEDE80BE550545F0B21E3F555A990F8004258"},
	{"Path/ML-DSA-87/1", "0D58219132746BE077DFE821E9F8FD87857B28AB91D6A567E312A73E2636032C", "3AA49EF72D010AEC19383BA1E83EC2DD3DCC207A96FFCEB9FFA269E3E3D66400"},
	{"Path/ML-DSA-87/2", "146C47AB9F88408EB76A813294D533B29D7E0FDA75DA5A4E7C69EB61EFEEBB78", "82C44F998A8D24F056084D0E80ECFD8434493385A284C69974923C270D397782"},
	{"Path/ML-DSA-87/3", "049D9B0B646A2AC7F50B63CE5E4BFE44C9B87634F4FF6C14C513E388B8A1F808", "FEBC9F8AE159002BE1A11D395959DD7FC20718135690CDAA2BCFB5801C02AB89"},
	{"Path/ML-DSA-87/4", "9823DDDE446A8EA883DAD3AC6477F79839FDC2D2DEF2416BE0A8B71CFBC3F5C6", "F7592C97C1A96A2F4053588F5CDAD4C50BF7C3752709854FA27779B445DD2BA2"},
	{"Path/ML-DSA-87/5", "AE213FE8589B414F53780D8B9B6837179967E13CB474C5AD365C043778D2BC90", "19C1913BA76FF04596BB7CC80FD825A5AEDEF5D5AD61CEDB5203E6D7EDB18877"},
	{"Count/ML-DSA-44/77", "090D97C1F4166EB32CA67C5FB564ACBE0735DB4AF4B8DB3A7C2CE7402357CA44", "E3838364B37F47EDFCA2B577B20B80C3CB51B9F56E0E4CDB7DF002C874039252"},
	{"Count/ML-DSA-44/100", "CFC73D07A883543A804F770070861825143A62F2F97D05FCE00FD8B25D29A43F", "0960C13E9BA467A938450120CC96FF6F04B7E557C99A838619A48F9A38738AB8"},
	{"Count/ML-DSA-65/64a", "26B605C78AC762FA1634C6F91DD117C4FBFF7F3A7E7781F0CC83B6281F04AD7F", "C9B07E7DDC0274468F312F5C692A54AC73D1E34D8638E20A2CD3C788F27D4355"},
	{"Count/ML-DSA-65/73", "9191CF381BEE17475C011986EFB6AFB1EFA6997442FD33427353F1DA1AA39FC0", "E616E36E81AA1EC39262109421AE0DDDA5E3B5A8F4A252BCA27AE882538DF618"},
	{"Count/ML-DSA-65/66", "516912C7B90A3DBE009B7478DBCAF0F5C5C9ED9699A20D0CA56CC516E5A444CD", "9247CA75F9456226A0C783DABCC33FF5B4B489575ADED543E74B29B45F9C8EF2"},
	{"Count/ML-DSA-65/65", "D4B841F882D50AB9E590066BAFABA0F0D04D32641C0B978E54CCAA69A6E8D2C4", "175231657B0F3C7065947999467C342064F29BFAEB553E97561407D5560E3AEB"},
	{"Count/ML-DSA-65/64b", "5492EB8D811072C030A30CC66B23A173059EBA0D4868CCB92FBE2510B4A5915F", "33D2753ED87D0003B44C1AF5F72EB931F559C6B4931AF7E249F65D3FA7613295"},
	{"Count/ML-DSA-87/64a", "B5C07ECEFE9E7C3B885FDEF032BDF9F807B4011E2DFE6806C088D2081631C8EB", "D1D5C2D167D6E62906790A5FEDF5A0A754CFAF47E6A11AEB93FB8C41934C31F8"},
	{"Count/ML-DSA-87/65", "E8FC3C9FAD711DDA2946334FBBD331468D6E9AB48EB86DCD03F300A17AEBC5E5", "3B435F7A2CE431C7AB8EAE0991C5DAC610827C99D27803046FBC6C567D6B71F2"},
	{"Count/ML-DSA-87/64b", "151F80886D6CE8C3B428964FE02C40CA0C8EFFA100EE089E54D785344FCCF719", "C628CE94D2AA99AA50CF15B147D4F9A9C62A3D4612152DE0A502C377F472D614"},
	{"Count/ML-DSA-87/64c", "48BEFFB4C97E59E474E1906F39888BE5AE62F6A011C05EF6A6B8D1E54F2171B7", "D2756A8FB4E47F796AF704ED0FC8C6E573D42DFAB443B329F00F8DB2FF12C465"},
	{"Count/ML-DSA-87/69", "FE2DA9DD93A077FCB6452AC88D0A5762EB896BAAAC6CE7D01CB1370BA8322390", "A86B29ADF2300D2636E21D4A350CD18E55A254379C3659A7A95D8734CEC1F005"},
}

var mldsaExternalMuTestCases = []mldsaExternalMuTestCase{
	// From crypto/internal/fips140/mldsa/mldsa_test.go BenchmarkCAST.
	{"CAST/ML-DSA-44", openssl.MLDSA44(), "5C624FCC1862452452D0C665840D8237F43108E5499EDCDC108FBC49D596E4B7", "2ad1c72bb0fcbe28099ce8bd2ed836dfebe520aad38fbac66ef785a3cfb10fb419327fa57818ee4e3718da4be48d24b59a208f8807271fdb7eda6e60141bd263"},
	{"CAST/ML-DSA-65", openssl.MLDSA65(), "F215BA2280D86F142012FC05FFC04F2C7D22FF5DD7D69AA0EFB081E3A53E9318", "35cdb7dddbed44af4641bac659f46598ed769ea9693fd4ed2152b84c45811d2e66eded1eb20cde1c1f4b82642a330d8e86ac432a2aefaa56cd9b2b5f4affd450"},
}

func TestMLDSARoundTrip(t *testing.T) {
	t.Parallel()
	for _, test := range mldsaParameterTests {
		t.Run(test.name, func(t *testing.T) {
			testMLDSARoundTrip(t, test.params)
		})
	}
}

func testMLDSARoundTrip(t *testing.T, params openssl.MLDSAParameters) {
	if !openssl.SupportsMLDSA(params) {
		t.Skipf("%s not supported on this platform", params)
	}
	t.Parallel()

	generated1, err := openssl.GenerateKeyMLDSA(params)
	if err != nil {
		t.Fatal(err)
	}
	generated2, err := openssl.GenerateKeyMLDSA(params)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(generated1.Bytes(), generated2.Bytes()) {
		t.Error("two generated private keys are equal")
	}
	if bytes.Equal(generated1.PublicKey().Bytes(), generated2.PublicKey().Bytes()) {
		t.Error("two generated public keys are equal")
	}

	for _, testCase := range mldsaACVPTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			seed := fromHexBytes(testCase.seed)
			privateKey, err := openssl.NewPrivateKeyMLDSA(params, seed)
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			if !bytes.Equal(privateKey.Bytes(), seed) {
				t.Error("private key seed changed")
			}

			publicKey := privateKey.PublicKey()
			publicKeyBytes := publicKey.Bytes()
			if len(publicKeyBytes) != params.PublicKeySize() {
				t.Fatalf("public key length = %d, want %d", len(publicKeyBytes), params.PublicKeySize())
			}
			reparsedPublicKey, err := openssl.NewPublicKeyMLDSA(params, publicKeyBytes)
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			if !bytes.Equal(reparsedPublicKey.Bytes(), publicKeyBytes) {
				t.Error("reparsed public key changed")
			}

			message := fromHexBytes(testCase.msg)
			signature, err := privateKey.Sign(message, "")
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(signature) != params.SignatureSize() {
				t.Fatalf("signature length = %d, want %d", len(signature), params.SignatureSize())
			}
			if err := reparsedPublicKey.Verify(message, signature, ""); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			wrongMessage := append([]byte(nil), message...)
			wrongMessage[0] ^= 0x80
			if err := reparsedPublicKey.Verify(wrongMessage, signature, ""); err == nil {
				t.Error("Verify passed on wrong message")
			}

			contextSignature, err := privateKey.Sign(message, "context")
			if err != nil {
				t.Fatalf("Sign with context: %v", err)
			}
			if err := reparsedPublicKey.Verify(message, contextSignature, "context"); err != nil {
				t.Fatalf("Verify with context: %v", err)
			}
			if err := reparsedPublicKey.Verify(message, contextSignature, "wrong context"); err == nil {
				t.Error("Verify passed with wrong context")
			}

			mu := append(fromHexBytes(testCase.msg), fromHexBytes(testCase.msg)...)
			externalSignature, err := privateKey.SignExternalMu(mu)
			if err != nil {
				t.Fatalf("SignExternalMu: %v", err)
			}
			if len(externalSignature) != params.SignatureSize() {
				t.Fatalf("external signature length = %d, want %d", len(externalSignature), params.SignatureSize())
			}
			if err := reparsedPublicKey.VerifyExternalMu(mu, externalSignature); err != nil {
				t.Fatalf("VerifyExternalMu: %v", err)
			}
			wrongMu := append([]byte(nil), mu...)
			wrongMu[0] ^= 0x80
			if err := reparsedPublicKey.VerifyExternalMu(wrongMu, externalSignature); err == nil {
				t.Error("VerifyExternalMu passed on wrong message")
			}
		})
	}
}

func TestMLDSABadLengths(t *testing.T) {
	t.Parallel()
	for _, test := range mldsaParameterTests {
		t.Run(test.name, func(t *testing.T) {
			testMLDSABadLengths(t, test.params)
		})
	}
}

func TestMLDSAExternalMuCASTVectors(t *testing.T) {
	t.Parallel()
	for _, test := range mldsaExternalMuTestCases {
		t.Run(test.name, func(t *testing.T) {
			if !openssl.SupportsMLDSA(test.params) {
				t.Skipf("%s not supported on this platform", test.params)
			}
			t.Parallel()
			privateKey, err := openssl.NewPrivateKeyMLDSA(test.params, fromHexBytes(test.seed))
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			publicKey := privateKey.PublicKey()
			mu := fromHexBytes(test.mu)

			signature, err := privateKey.SignExternalMu(mu)
			if err != nil {
				t.Fatalf("SignExternalMu: %v", err)
			}
			if len(signature) != test.params.SignatureSize() {
				t.Fatalf("signature length = %d, want %d", len(signature), test.params.SignatureSize())
			}
			if err := publicKey.VerifyExternalMu(mu, signature); err != nil {
				t.Fatalf("VerifyExternalMu: %v", err)
			}
			wrongMu := append([]byte(nil), mu...)
			wrongMu[0] ^= 0x80
			if err := publicKey.VerifyExternalMu(wrongMu, signature); err == nil {
				t.Error("VerifyExternalMu passed on wrong message")
			}
		})
	}
}

func testMLDSABadLengths(t *testing.T, params openssl.MLDSAParameters) {
	if !openssl.SupportsMLDSA(params) {
		t.Skipf("%s not supported on this platform", params)
	}
	t.Parallel()
	privateKey, err := openssl.GenerateKeyMLDSA(params)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBytes := privateKey.Bytes()
	publicKeyBytes := privateKey.PublicKey().Bytes()
	publicKey, err := openssl.NewPublicKeyMLDSA(params, publicKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("message")
	signature, err := privateKey.Sign(message, "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := openssl.NewPrivateKeyMLDSA(params, privateKeyBytes[:len(privateKeyBytes)-1]); err == nil {
		t.Error("NewPrivateKey accepted a short seed")
	}
	if _, err := openssl.NewPrivateKeyMLDSA(params, append(privateKeyBytes, 0)); err == nil {
		t.Error("NewPrivateKey accepted a long seed")
	}
	if _, err := openssl.NewPublicKeyMLDSA(params, publicKeyBytes[:len(publicKeyBytes)-1]); err == nil {
		t.Error("NewPublicKey accepted a short encoding")
	}
	if _, err := openssl.NewPublicKeyMLDSA(params, append(publicKeyBytes, 0)); err == nil {
		t.Error("NewPublicKey accepted a long encoding")
	}
	if err := publicKey.Verify(message, signature[:params.SignatureSize()-1], ""); err == nil {
		t.Error("Verify accepted a short signature")
	}
	if err := publicKey.Verify(message, append(signature, 0), ""); err == nil {
		t.Error("Verify accepted a long signature")
	}
	if _, err := privateKey.Sign(message, string(make([]byte, 256))); err == nil {
		t.Error("Sign accepted a long context")
	}
	if _, err := privateKey.SignExternalMu(make([]byte, 63)); err == nil {
		t.Error("SignExternalMu accepted a short mu")
	}
	if err := publicKey.VerifyExternalMu(make([]byte, 63), signature); err == nil {
		t.Error("VerifyExternalMu accepted a short mu")
	}
}

func TestMLDSAConstantSizes(t *testing.T) {
	// Sanity-check the package-private size constants against the publicly
	// observable parameter set values.
	if openssl.PrivateKeySizeMLDSA != 32 {
		t.Errorf("PrivateKeySizeMLDSA = %d, want 32", openssl.PrivateKeySizeMLDSA)
	}
	if openssl.MLDSA44().PublicKeySize() != openssl.PublicKeySizeMLDSA44 {
		t.Errorf("MLDSA44 public key size mismatch")
	}
	if openssl.MLDSA65().PublicKeySize() != openssl.PublicKeySizeMLDSA65 {
		t.Errorf("MLDSA65 public key size mismatch")
	}
	if openssl.MLDSA87().PublicKeySize() != openssl.PublicKeySizeMLDSA87 {
		t.Errorf("MLDSA87 public key size mismatch")
	}
	if openssl.MLDSA44().SignatureSize() != openssl.SignatureSizeMLDSA44 {
		t.Errorf("MLDSA44 signature size mismatch")
	}
	if openssl.MLDSA65().SignatureSize() != openssl.SignatureSizeMLDSA65 {
		t.Errorf("MLDSA65 signature size mismatch")
	}
	if openssl.MLDSA87().SignatureSize() != openssl.SignatureSizeMLDSA87 {
		t.Errorf("MLDSA87 signature size mismatch")
	}
}

func BenchmarkMLDSAKeyGen(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			if !openssl.SupportsMLDSA(test.params) {
				b.Skipf("%s not supported on this platform", test.params)
			}
			b.ReportAllocs()
			for b.Loop() {
				privateKey, err := openssl.GenerateKeyMLDSA(test.params)
				if err != nil {
					b.Fatal(err)
				}
				sink ^= privateKey.Bytes()[0]
			}
		})
	}
}

func BenchmarkMLDSAPublicKey(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			if !openssl.SupportsMLDSA(test.params) {
				b.Skipf("%s not supported on this platform", test.params)
			}
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				publicKey := privateKey.PublicKey()
				sink ^= publicKey.Bytes()[0]
			}
		})
	}
}

func BenchmarkMLDSASign(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			if !openssl.SupportsMLDSA(test.params) {
				b.Skipf("%s not supported on this platform", test.params)
			}
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			message := []byte("testing")
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				signature, err := privateKey.Sign(message, "")
				if err != nil {
					b.Fatal(err)
				}
				sink ^= signature[0]
			}
		})
	}
}

func BenchmarkMLDSASignExternalMu(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			if !openssl.SupportsMLDSA(test.params) {
				b.Skipf("%s not supported on this platform", test.params)
			}
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			mu := make([]byte, 64)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				signature, err := privateKey.SignExternalMu(mu)
				if err != nil {
					b.Fatal(err)
				}
				sink ^= signature[0]
			}
		})
	}
}

func BenchmarkMLDSAVerify(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			if !openssl.SupportsMLDSA(test.params) {
				b.Skipf("%s not supported on this platform", test.params)
			}
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			publicKey := privateKey.PublicKey()
			message := []byte("testing")
			signature, err := privateKey.Sign(message, "")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := publicKey.Verify(message, signature, ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMLDSAVerifyExternalMu(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			if !openssl.SupportsMLDSA(test.params) {
				b.Skipf("%s not supported on this platform", test.params)
			}
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			publicKey := privateKey.PublicKey()
			mu := make([]byte, 64)
			signature, err := privateKey.SignExternalMu(mu)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := publicKey.VerifyExternalMu(mu, signature); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func newBenchmarkMLDSAPrivateKey(b *testing.B, params openssl.MLDSAParameters) *openssl.PrivateKeyMLDSA {
	b.Helper()
	seed := make([]byte, 32)
	privateKey, err := openssl.NewPrivateKeyMLDSA(params, seed)
	if err != nil {
		b.Fatal(err)
	}
	return privateKey
}

func fromHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
