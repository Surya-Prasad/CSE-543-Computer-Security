#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>

#include "cse543-ssl.h"

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	    int aad_len, unsigned char *key, unsigned char *iv,
	    unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Optionally add AAD (kept commented as in original) */
	/*
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();
	*/

	/* Encrypt */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise (no extra bytes for GCM) */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	    int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
	    unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		handleErrors();

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Optionally add AAD (kept commented as in original) */
	/*
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();
	*/

	/* Decrypt */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Set expected tag */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/* Finalise: positive => success */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		plaintext_len += len;
		return plaintext_len;
	} else {
		return -1; /* auth failed */
	}
}

/* UPDATED: use EVP_MD_CTX_new/free (OpenSSL 1.1+) */
void digest_message(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if(mdctx == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handleErrors();

	*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
	if(*digest == NULL)
		handleErrors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handleErrors();

	EVP_MD_CTX_free(mdctx);
}

/* UPDATED: HMAC with opaque HMAC_CTX and correct key length */
int hmac_message(unsigned char* msg, size_t mlen, unsigned char** val, size_t* vlen, unsigned char *key, size_t key_len)
{
	const EVP_MD* md = EVP_sha256();
	unsigned int out_len = 0;
	int ok = 0;

	/* allocate output buffer once (SHA-256 = 32 bytes) */
	*val = (unsigned char*)OPENSSL_malloc(EVP_MD_size(md));
	if (*val == NULL) return 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	if(!HMAC_Init_ex(&ctx, key, (int)key_len, md, NULL)) goto done_legacy;
	if(!HMAC_Update(&ctx, msg, mlen))                     goto done_legacy;
	if(!HMAC_Final(&ctx, *val, &out_len))                 goto done_legacy;

	ok = 1;
done_legacy:
	HMAC_CTX_cleanup(&ctx);
#else
	HMAC_CTX *ctx = HMAC_CTX_new();
	if (!ctx) { OPENSSL_free(*val); *val = NULL; return 0; }

	if(!HMAC_Init_ex(ctx, key, (int)key_len, md, NULL)) goto done;
	if(!HMAC_Update(ctx, msg, mlen))                    goto done;
	if(!HMAC_Final(ctx, *val, &out_len))                goto done;

	ok = 1;
done:
	HMAC_CTX_free(ctx);
#endif

	if (ok) { *vlen = (size_t)out_len; }
	else { OPENSSL_free(*val); *val = NULL; }
	return ok;
}

int rsa_encrypt(unsigned char *msg, unsigned int msgLen, unsigned char **encMsg, unsigned char **ek,
	       unsigned int *ekl, unsigned char **iv, unsigned int *ivl, EVP_PKEY *pubkey) 
{
	unsigned int encMsgLen = 0;
	unsigned int blockLen  = 0;
	EVP_CIPHER_CTX *rsaEncryptCtx;

	*ivl = EVP_MAX_IV_LENGTH;
	*ekl = EVP_PKEY_size(pubkey);
	*ek = (unsigned char*)malloc(*ekl);
	*iv = (unsigned char*)malloc(*ivl);
	if(*ek == NULL || *iv == NULL) return -1;
	memset( *iv, 0, *ivl );  // TJ: added

	*encMsg = (unsigned char*)malloc(msgLen + *ivl);
	if(encMsg == NULL) return -1;

	if(!(rsaEncryptCtx = EVP_CIPHER_CTX_new())) handleErrors();

	if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), ek, (int *)ekl, *iv, &pubkey, 1)) {
		handleErrors();
	}

	if(!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, (int *)&blockLen, msg, msgLen)) {
		handleErrors();
	}
	encMsgLen += blockLen;

	if(!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, (int *)&blockLen)) {
		handleErrors();
	}
	encMsgLen += blockLen;

	/* UPDATED: free instead of cleanup */
	EVP_CIPHER_CTX_free(rsaEncryptCtx);

	return (int)encMsgLen;
}

int rsa_decrypt(unsigned char *encMsg, unsigned int encMsgLen, unsigned char *ek, unsigned int ekl,
	       unsigned char *iv, unsigned int ivl, unsigned char **decMsg, EVP_PKEY *privkey)
{
	unsigned int decLen   = 0;
	unsigned int blockLen = 0;
	EVP_CIPHER_CTX *rsaDecryptCtx;

	*decMsg = (unsigned char*)malloc(encMsgLen + ivl);
	if(decMsg == NULL) return -1;

	if(!(rsaDecryptCtx = EVP_CIPHER_CTX_new())) handleErrors();

	if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_cbc(), ek, ekl, iv, privkey)) {
		handleErrors();
	}

	if(!EVP_OpenUpdate(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen, encMsg, (int)encMsgLen)) {
		handleErrors();
	}
	decLen += blockLen;

	if(!EVP_OpenFinal(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) {
		handleErrors();
	}
	decLen += blockLen;

	/* UPDATED: free instead of cleanup */
	EVP_CIPHER_CTX_free(rsaDecryptCtx);

	return (int)decLen;
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}
