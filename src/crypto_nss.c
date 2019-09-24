/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/* BEGIN SQLCIPHER */
#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_NSS
#include "crypto.h"
#include "sqlcipher.h"
#include <nss/blapit.h>
#include <nss/nss.h>
#include <nss/pk11pub.h>

static NSSInitContext* nss_init_context = NULL;
static unsigned int nss_init_count = 0;
static sqlite3_mutex* nss_rand_mutex = NULL;

int sqlcipher_nss_setup(sqlcipher_provider *p);

static int sqlcipher_nss_activate(void *ctx) {
  CODEC_TRACE_MUTEX("sqlcipher_nss_activate: entering static master mutex\n");
  sqlite3_mutex_enter(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_nss_activate: entered static master mutex\n");
  if (nss_init_context == NULL) {
    nss_init_context = NSS_InitContext("", "", "", "", NULL,
                        NSS_INIT_READONLY | NSS_INIT_NOCERTDB | NSS_INIT_NOMODDB |
                        NSS_INIT_FORCEOPEN | NSS_INIT_OPTIMIZESPACE | NSS_INIT_NOROOTINIT);
  }
  nss_init_count++;
  CODEC_TRACE_MUTEX("sqlcipher_nss_activate: leaving static master mutex\n");
  sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_nss_activate: left static master mutex\n");
  return SQLITE_OK;
}

static int sqlcipher_nss_deactivate(void *ctx) {
  CODEC_TRACE_MUTEX("sqlcipher_nss_deactivate: entering static master mutex\n");
  sqlite3_mutex_enter(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_nss_deactivate: entered static master mutex\n");
  nss_init_count--;
  if (nss_init_count == 0 && nss_init_context != NULL) {
    NSS_ShutdownContext(nss_init_context);
    nss_init_context = NULL;
  }
  CODEC_TRACE_MUTEX("sqlcipher_nss_deactivate: leaving static master mutex\n");
  sqlite3_mutex_leave(sqlite3_mutex_alloc(SQLITE_MUTEX_STATIC_MASTER));
  CODEC_TRACE_MUTEX("sqlcipher_nss_deactivate: left static master mutex\n");
  return SQLITE_OK;
}

static int sqlcipher_nss_add_random(void *ctx, void *buffer, int length) {
  return SQLITE_OK;
}

/* generate a defined number of random bytes */
static int sqlcipher_nss_random (void *ctx, void *buffer, int length) {
  // PK11_GenerateRandom should be thread-safe.
  return (PK11_GenerateRandom((unsigned char *)buffer, length) == SECSuccess) ? SQLITE_OK : SQLITE_ERROR;
}

static const char* sqlcipher_nss_get_provider_name(void *ctx) {
  return "nss";
}

static const char* sqlcipher_nss_get_provider_version(void *ctx) {
  return NSS_GetVersion();
}

static const char* sqlcipher_nss_get_cipher(void *ctx) {
  return "aes-256-cbc";
}

static int sqlcipher_nss_get_key_sz(void *ctx) {
  return AES_256_KEY_LENGTH;
}

static int sqlcipher_nss_get_iv_sz(void *ctx) {
  return AES_BLOCK_SIZE;
}

static int sqlcipher_nss_get_block_sz(void *ctx) {
  return AES_BLOCK_SIZE;
}

static int sqlcipher_nss_get_hmac_sz(void *ctx, int algorithm) {
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      return SHA1_LENGTH;
      break;
    case SQLCIPHER_HMAC_SHA256:
      return SHA256_LENGTH;
      break;
    case SQLCIPHER_HMAC_SHA512:
      return SHA512_LENGTH;
      break;
    default:
      return 0;
  }
}

static int sqlcipher_nss_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  int rc = SQLITE_OK;
  unsigned int length;
  unsigned int outLen;
  PK11Context* context = NULL;
  PK11SlotInfo * slot = NULL;
  PK11SymKey* symKey = NULL;
  if(in == NULL) goto error;
  CK_MECHANISM_TYPE mech;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      mech = CKM_SHA_1_HMAC;
      break;
    case SQLCIPHER_HMAC_SHA256:
      mech = CKM_SHA256_HMAC;
      break;
    case SQLCIPHER_HMAC_SHA512:
      mech = CKM_SHA512_HMAC;
      break;
    default:
      goto error;
  }
  length = sqlcipher_nss_get_hmac_sz(ctx, algorithm);
  slot = PK11_GetInternalSlot();
  if (slot == NULL) goto error;
  SECItem keyItem;
  keyItem.data = hmac_key;
  keyItem.len = key_sz;
  symKey = PK11_ImportSymKey(slot, mech, PK11_OriginUnwrap,
                             CKA_SIGN, &keyItem, NULL);
  if (symKey == NULL) goto error;
  SECItem noParams;
  noParams.data = 0;
  noParams.len = 0;
  context = PK11_CreateContextBySymKey(mech, CKA_SIGN, symKey, &noParams);
  if (context == NULL) goto error;
  if (PK11_DigestBegin(context) != SECSuccess) goto error;
  if (PK11_DigestOp(context, in, in_sz) != SECSuccess) goto error;
  if (in2 != NULL) {
    if (PK11_DigestOp(context, in2, in2_sz) != SECSuccess) goto error;
  }
  if (PK11_DigestFinal(context, out, &outLen, length) != SECSuccess) goto error;

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    if (context) PK11_DestroyContext(context, PR_TRUE);
    if (symKey) PK11_FreeSymKey(symKey);
    if (slot) PK11_FreeSlot(slot);
    return rc;
}

static int sqlcipher_nss_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc = SQLITE_OK;
  PK11SlotInfo * slot = NULL;
  SECAlgorithmID * algid = NULL;
  PK11SymKey* symKey = NULL;
  SECOidTag oidtag;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      oidtag = SEC_OID_HMAC_SHA1;
      break;
    case SQLCIPHER_HMAC_SHA256:
      oidtag = SEC_OID_HMAC_SHA256;
      break;
    case SQLCIPHER_HMAC_SHA512:
      oidtag = SEC_OID_HMAC_SHA512;
      break;
    default:
      goto error;
  }
  SECItem secSalt;
  secSalt.data = salt;
  secSalt.len = salt_sz;
  // Always pass SEC_OID_HMAC_SHA1 (i.e. PBMAC1) as this parameter
  // is unused for key generation. It is currently only used
  // for PBKDF2 authentication or key (un)wrapping when specifying an
  // encryption algorithm (PBES2).
  algid = PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2, SEC_OID_HMAC_SHA1,
                                      oidtag, key_sz, workfactor, &secSalt);
  if (algid == NULL) goto error;
  slot = PK11_GetInternalSlot();
  if (slot == NULL) goto error;
  SECItem pwItem;
  pwItem.data = (unsigned char *) pass; // PK11_PBEKeyGen doesn't modify the key.
  pwItem.len = pass_sz;
  symKey = PK11_PBEKeyGen(slot, algid, &pwItem, PR_FALSE, NULL);
  if (symKey == NULL) goto error;
  if (PK11_ExtractKeyValue(symKey) != SECSuccess) goto error;
  // No need to free keyData as it is a buffer managed by symKey.
  SECItem* keyData = PK11_GetKeyData(symKey);
  if (keyData == NULL) goto error;
  memcpy(key, keyData->data, key_sz);

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    if (slot) PK11_FreeSlot(slot);
    if (algid) SECOID_DestroyAlgorithmID(algid, PR_TRUE);
    if (symKey) PK11_FreeSymKey(symKey);
    return rc;
}

static int sqlcipher_nss_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  int rc = SQLITE_OK;
  PK11SlotInfo * slot = NULL;
  PK11SymKey* symKey = NULL;
  unsigned int outLen;
  SECItem params;
  params.data = iv;
  params.len = sqlcipher_nss_get_iv_sz(ctx);
  slot = PK11_GetInternalSlot();
  if (slot == NULL) goto error;
  SECItem keyItem;
  keyItem.data = key;
  keyItem.len = key_sz;
  symKey = PK11_ImportSymKey(slot, CKM_AES_CBC, PK11_OriginUnwrap,
                             CKA_ENCRYPT, &keyItem, NULL);
  if (symKey == NULL) goto error;
  SECStatus rv;
  if (mode == CIPHER_ENCRYPT) {
    rv = PK11_Encrypt(symKey, CKM_AES_CBC, &params, out, &outLen,
                      in_sz + 16, in, in_sz);
  } else {
    rv = PK11_Decrypt(symKey, CKM_AES_CBC, &params, out, &outLen,
                      in_sz + 16, in, in_sz);
  }
  if (rv != SECSuccess) goto error;

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    if (slot) PK11_FreeSlot(slot);
    if (symKey) PK11_FreeSymKey(symKey);
    return rc;
}

static int sqlcipher_nss_ctx_copy(void *target_ctx, void *source_ctx) {
  return SQLITE_OK;
}

static int sqlcipher_nss_ctx_cmp(void *c1, void *c2) {
  return 1; /* always indicate contexts are the same */
}

static int sqlcipher_nss_ctx_init(void **ctx) {
  sqlcipher_nss_activate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_nss_ctx_free(void **ctx) {
  sqlcipher_nss_deactivate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_nss_fips_status(void *ctx) {
  return 0;
}

int sqlcipher_nss_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_nss_activate;
  p->deactivate = sqlcipher_nss_deactivate;
  p->random = sqlcipher_nss_random;
  p->get_provider_name = sqlcipher_nss_get_provider_name;
  p->hmac = sqlcipher_nss_hmac;
  p->kdf = sqlcipher_nss_kdf;
  p->cipher = sqlcipher_nss_cipher;
  p->get_cipher = sqlcipher_nss_get_cipher;
  p->get_key_sz = sqlcipher_nss_get_key_sz;
  p->get_iv_sz = sqlcipher_nss_get_iv_sz;
  p->get_block_sz = sqlcipher_nss_get_block_sz;
  p->get_hmac_sz = sqlcipher_nss_get_hmac_sz;
  p->ctx_copy = sqlcipher_nss_ctx_copy;
  p->ctx_cmp = sqlcipher_nss_ctx_cmp;
  p->ctx_init = sqlcipher_nss_ctx_init;
  p->ctx_free = sqlcipher_nss_ctx_free;
  p->add_random = sqlcipher_nss_add_random;
  p->fips_status = sqlcipher_nss_fips_status;
  p->get_provider_version = sqlcipher_nss_get_provider_version;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
