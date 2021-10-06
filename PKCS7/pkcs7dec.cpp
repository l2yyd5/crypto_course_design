#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/sm2.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace std;

string cacert(
    "\
-----BEGIN CERTIFICATE----- \n\
MIIB/zCCAaagAwIBAgIJAKKa0PAt9M1FMAoGCCqBHM9VAYN1MFsxCzAJBgNVBAYT \n\
AkNOMQ4wDAYDVQQIDAVIdUJlaTEOMAwGA1UEBwwFV3VIYW4xDTALBgNVBAoMBEhV \n\
U1QxDDAKBgNVBAsMA0NTRTEPMA0GA1UEAwwGY2Fyb290MB4XDTIwMDkyMDIwNTkx \n\
OVoXDTMwMDkxODIwNTkxOVowWzELMAkGA1UEBhMCQ04xDjAMBgNVBAgMBUh1QmVp \n\
MQ4wDAYDVQQHDAVXdUhhbjENMAsGA1UECgwESFVTVDEMMAoGA1UECwwDQ1NFMQ8w \n\
DQYDVQQDDAZjYXJvb3QwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASJ8mm28JJR \n\
bZKLr6DCo1+KWimpKEsiTfZM19Zi5ao7Au6YLosyN71256MWmjwkwXxJeLa0lCfm \n\
kF/YWCX6qGQ0o1MwUTAdBgNVHQ4EFgQUAL5hW3RUzqvsiTzIc1gUHeK5uzQwHwYD \n\
VR0jBBgwFoAUAL5hW3RUzqvsiTzIc1gUHeK5uzQwDwYDVR0TAQH/BAUwAwEB/zAK \n\
BggqgRzPVQGDdQNHADBEAiAaZMmvE5zzXHx/TBgdUhjtpRH3Jpd6OZ+SOAfMtKxD \n\
LAIgdKq/v2Jkmn37Y9U8FHYDfFqk5I0qlQOAmuvbVUi3yvM= \n\
-----END CERTIFICATE----- \n\
");

string pkeyB(
    "\
-----BEGIN EC PARAMETERS----- \n\
BggqgRzPVQGCLQ== \n\
-----END EC PARAMETERS----- \n\
-----BEGIN EC PRIVATE KEY----- \n\
MHcCAQEEINQhCKslrI3tKt6cK4Kxkor/LBvM8PSv699Xea7kTXTToAoGCCqBHM9V \n\
AYItoUQDQgAEH7rLLiFASe3SWSsGbxFUtfPY//pXqLvgM6ROyiYhLkPxEulwrTe8 \n\
kv5R8/NA7kSSvcsGIQ9EPWhr6HnCULpklw== \n\
-----END EC PRIVATE KEY----- \n\
");

PKCS7* getPKCS7(const char* pkcs7str) {
	BIO* pkcs7Bio = BIO_new_mem_buf((char*)pkcs7str, strlen(pkcs7str));
	if (!pkcs7Bio) return nullptr;
	return PEM_read_bio_PKCS7(pkcs7Bio, nullptr, nullptr, nullptr);
}
X509 *getX509(const char *cert) {
  BIO *bio;
  bio = BIO_new(BIO_s_mem());
  BIO_puts(bio, cert);
  return PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
}
EVP_PKEY *getpkey(const char *private_key) {
  BIO *bio_pkey = BIO_new_mem_buf((char *)private_key, strlen(private_key));
  if (bio_pkey == nullptr) return nullptr;
  return PEM_read_bio_PrivateKey(bio_pkey, nullptr, nullptr, nullptr);
}

bool verifySig(PKCS7* p7, BIO* p7Bio, X509* tcacert) {
	STACK_OF(PKCS7_SIGNER_INFO)* sk = PKCS7_get_signer_info(p7);
	if (!sk) return false;
	X509_STORE* store = X509_STORE_new();
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	X509_STORE_add_cert(store, tcacert);	
	int sigNum = sk_PKCS7_SIGNER_INFO_num(sk);
	bool ret = true;
	for (int i = 0; i < sigNum; ++i) {
		PKCS7_SIGNER_INFO* sigInfo = sk_PKCS7_SIGNER_INFO_value(sk, i);
		auto res = PKCS7_dataVerify(store, ctx, p7Bio, p7, sigInfo);
		PKCS7_SIGNER_INFO_free(sigInfo);
		if (res <= 0) {
			ret = false;
			break;
		}
	}	
	X509_STORE_free(store);
	X509_STORE_CTX_free(ctx);
	sk_PKCS7_SIGNER_INFO_free(sk);
	return ret;
}

inline void reterror() {
  cout << "ERROR" << endl;
  exit(0);
}

int main() {
  OpenSSL_add_all_algorithms();

  char buf[4096];
  char* pkcs7str = (char *) mmap(NULL,  lseek(0, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fileno(stdin), 0);
  // char pkcs7str[4096];
  PKCS7 *p7;
  BIO *input;
  BIO *p7bio = nullptr;
  BIO *out = BIO_new(BIO_s_file());
  X509 *certs = nullptr;

	// fread(pkcs7str, sizeof(pkcs7str) - 1, 1, stdin);
  BIO_set_fp(out, stdout, BIO_NOCLOSE);

  p7 = getPKCS7(pkcs7str);
  if (!p7) reterror();

  p7bio = PKCS7_dataDecode(p7, getpkey(pkeyB.c_str()), nullptr, nullptr);
  if (!p7bio) reterror();

  certs = getX509(cacert.c_str());
  if (!certs) reterror();

  int retLen = BIO_read(p7bio, buf, sizeof(buf));
  if(retLen <= 0) reterror();

  if(!verifySig(p7, p7bio, certs)) reterror();
  BIO_write(out, buf, retLen);

  X509_free(certs);
  return 0;
}