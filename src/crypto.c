/* 
** SQLite Cipher
** crypto.c developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** Copyright (c) 2008, ZETETIC LLC
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
/* BEGIN CRYPTO */
#ifdef SQLITE_HAS_CODEC

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include "sqliteInt.h"
#include "btreeInt.h"
#include "crypto.h"


typedef struct {
  int key_sz;
  int iv_sz;
  int pass_sz;
  int rekey_plaintext;
  void *key;
  void *buffer;
  void *rekey;
  void *salt;
  void *pass;
  Btree *pBt;
} codec_ctx;

/* 
 * The following two functions PKCS5_PBKDF2_HMAC_SHA256 and h__dump implement a 
 * PBKDF2 (rfc2898) variant using SHA 256 instead of SHA1. These functions were extracted directly from 
 * from openssl-0.9.8j crypto/evp/p5_crpt2.c. The only modifications have been to use a variable 
 * defined HMAC_HASH to allow selection of the message digest (instead of fixing it to EVP_sha1().
 * - Stephen
*/

#ifdef DEBUG_PKCS5V2
static void h__dump (const unsigned char *p, int len)
{
  for (; len --; p++) fprintf(stderr, "%02X ", *p);
  fprintf(stderr, "\n");
}
#endif


 /* This is an implementation of PKCS#5 v2.0 password based encryption key
 * derivation function PBKDF2 using the only currently defined function HMAC
 * with SHA1. Verified against test vectors posted by Peter Gutmann
 * <pgut001@cs.auckland.ac.nz> to the PKCS-TNG <pkcs-tng@rsa.com> mailing list.
 */
static int PKCS5_PBKDF2_HMAC_SHA256(const char *pass, int passlen,
         const unsigned char *salt, int saltlen, int iter,
         int keylen, unsigned char *out)
{
  unsigned char digtmp[SHA_DIGEST_LENGTH], *p, itmp[4];
  int cplen, j, k, tkeylen;
  unsigned long i = 1;
  HMAC_CTX hctx;

  HMAC_CTX_init(&hctx);
  p = out;
  tkeylen = keylen;
  if(!pass) passlen = 0;
  else if(passlen == -1) passlen = strlen(pass);
  while(tkeylen) {
    if(tkeylen > SHA_DIGEST_LENGTH) cplen = SHA_DIGEST_LENGTH;
    else cplen = tkeylen;
    /* We are unlikely to ever use more than 256 blocks (5120 bits!)
     * but just in case...
     */
    itmp[0] = (unsigned char)((i >> 24) & 0xff);
    itmp[1] = (unsigned char)((i >> 16) & 0xff);
    itmp[2] = (unsigned char)((i >> 8) & 0xff);
    itmp[3] = (unsigned char)(i & 0xff);
    HMAC_Init_ex(&hctx, pass, passlen, HMAC_HASH, NULL);
    HMAC_Update(&hctx, salt, saltlen);
    HMAC_Update(&hctx, itmp, 4);
    HMAC_Final(&hctx, digtmp, NULL);
    memcpy(p, digtmp, cplen);
    for(j = 1; j < iter; j++) {
      HMAC(HMAC_HASH, pass, passlen,
         digtmp, SHA_DIGEST_LENGTH, digtmp, NULL);
      for(k = 0; k < cplen; k++) p[k] ^= digtmp[k];
    }
    tkeylen-= cplen;
    i++;
    p+= cplen;
  }
  HMAC_CTX_cleanup(&hctx);
#ifdef DEBUG_PKCS5V2
  fprintf(stderr, "Password:\n");
  h__dump (pass, passlen);
  fprintf(stderr, "Salt:\n");
  h__dump (salt, saltlen);
  fprintf(stderr, "Iteration count %d\n", iter);
  fprintf(stderr, "Key:\n");
  h__dump (out, keylen);
#endif
  return 1;
}

static void codec_prepare_key(sqlite3 *db, const void *zKey, int nKey, void *salt, int nSalt, void *out, int *nOut) {
  /* if key data lenth is exactly 256 bits / 32 bytes use the data directly */
  if (nKey == 35 && sqlite3StrNICmp(zKey ,"x'", 2) == 0) { 
    int n = nKey - 3; /* adjust for leading x' and tailing ' */
    int half_n = n/2;
    const char *z = zKey + 2; /* adjust lead offset of x' */ 
    void *key = sqlite3HexToBlob(db, z, n);
    memcpy(out, key, half_n);
    *nOut = half_n;
    memset(key, 0, half_n); /* cleanup temporary key data */
    sqlite3DbFree(db, key);
    fprintf(stderr, "\nusing hex key\n"); 
  /* otherwise the key is provided as a string so hash it to get key data */
  } else {
    *nOut = SHA_DIGEST_LENGTH;
    PKCS5_PBKDF2_HMAC_SHA256(zKey, nKey, salt, nSalt, PBKDF2_ITER, SHA_DIGEST_LENGTH, out);
  }
}

/*
 * ctx - codec context
 * pgno - page number in database
 * size - size in bytes of input and output buffers
 * mode - 1 to encrypt, 0 to decrypt
 * in - pointer to input bytes
 * out - pouter to output bytes
 */
static int codec_cipher(codec_ctx *ctx, Pgno pgno, int mode, int size, void *in, void *out) {
  EVP_CIPHER_CTX ectx;
  void *iv;
  int tmp_csz, csz;

  /* when this is an encryption operation and rekey is not null, we will actually encrypt
  ** data with the new rekey data */
  void *key = ((mode == CIPHER_ENCRYPT && ctx->rekey != NULL) ? ctx->rekey : ctx->key);

  /* just copy raw data from in to out whenever 
  ** 1. key is NULL; or 
  ** 2. this is a decrypt operation and rekey_plaintext is true
  */ 
  if(key == NULL || (mode==CIPHER_DECRYPT && ctx->rekey_plaintext)) {
    memcpy(out, in, size);
    return SQLITE_OK;
  } 

  size = size - ctx->iv_sz; /* adjust size to useable size and memset reserve at end of page */
  iv = out + size;
  if(mode == CIPHER_ENCRYPT) {
    RAND_pseudo_bytes(iv, ctx->iv_sz);
  } else {
    memcpy(iv, in+size, ctx->iv_sz);
  } 
  
  EVP_CipherInit(&ectx, CIPHER, NULL, NULL, mode);
  EVP_CIPHER_CTX_set_padding(&ectx, 0);
  EVP_CipherInit(&ectx, NULL, key, iv, mode);
  EVP_CipherUpdate(&ectx, out, &tmp_csz, in, size);
  csz = tmp_csz;  
  out += tmp_csz;
  EVP_CipherFinal(&ectx, out, &tmp_csz);
  csz += tmp_csz;
  EVP_CIPHER_CTX_cleanup(&ectx);
  assert(size == csz);

  return SQLITE_OK;
}

/*
 * sqlite3Codec can be called in multiple modes.
 * encrypt mode - expected to return a pointer to the 
 *   encrypted data without altering pData.
 * decrypt mode - expected to return a pointer to pData, with
 *   the data decrypted in the input buffer
 */
void* sqlite3Codec(void *iCtx, void *pData, Pgno pgno, int mode) {
  int emode;
  codec_ctx *ctx = (codec_ctx *) iCtx;
  int pg_sz = sqlite3BtreeGetPageSize(ctx->pBt);
 
  switch(mode) {
    case 0: /* decrypt */
    case 2:
    case 3:
      emode = CIPHER_DECRYPT;
      break;
    case 6: /* encrypt */
    case 7:
      emode = CIPHER_ENCRYPT;
      break;
    default:
      return pData;
      break;
  }

  if(pgno == 1) { 
    /* if this is a read & decrypt operation on the first page then copy the 
       first 16 bytes off the page into the context's random salt buffer
    */
    if(emode == CIPHER_ENCRYPT) {
      memcpy(ctx->buffer, ctx->salt, FILE_HEADER_SZ);
    } else {
      memcpy(ctx->buffer, SQLITE_FILE_HEADER, FILE_HEADER_SZ);
    }
    
    /* adjust starting pointers in data page for header offset */
    codec_cipher(ctx, pgno, emode, pg_sz - FILE_HEADER_SZ, pData + FILE_HEADER_SZ, ctx->buffer + FILE_HEADER_SZ);
  } else {
    codec_cipher(ctx, pgno, emode, pg_sz, pData, ctx->buffer);
  }
 
  if(emode == CIPHER_ENCRYPT) {
    return ctx->buffer; /* return persistent buffer data, pData remains intact */
  } else {
    memcpy(pData, ctx->buffer, pg_sz); /* copy buffer data back to pData and return */
    return pData;
  }
}

int sqlite3CodecAttach(sqlite3* db, int nDb, const void *zKey, int nKey) {
  struct Db *pDb = &db->aDb[nDb];
  
  if(nKey && zKey && pDb->pBt) {
    codec_ctx *ctx;
    Pager *pPager = pDb->pBt->pBt->pPager;
    int prepared_key_sz;

    ctx = sqlite3Malloc(sizeof(codec_ctx));
    if(ctx == NULL) return SQLITE_NOMEM;
    memset(ctx, 0, sizeof(codec_ctx)); /* initialize all pointers and values to 0 */
 
    ctx->pBt = pDb->pBt; /* assign pointer to database btree structure */
    
    /* pre-allocate a page buffer of PageSize bytes. This will
       be used as a persistent buffer for encryption and decryption 
       operations to avoid overhead of multiple memory allocations*/
    ctx->buffer = sqlite3Malloc(sqlite3BtreeGetPageSize(ctx->pBt));
    if(ctx->buffer == NULL) return SQLITE_NOMEM;
       
    ctx->key_sz = EVP_CIPHER_key_length(CIPHER);
    ctx->iv_sz = EVP_CIPHER_iv_length(CIPHER);
    
    /* allocate space for salt data */
    ctx->salt = sqlite3Malloc(FILE_HEADER_SZ);
    if(ctx->salt == NULL) return SQLITE_NOMEM;
    
    /* allocate space for salt data */
    ctx->key = sqlite3Malloc(ctx->key_sz);
    if(ctx->key == NULL) return SQLITE_NOMEM;
   
    /* allocate space for raw key data */
    ctx->pass = sqlite3Malloc(nKey);
    if(ctx->pass == NULL) return SQLITE_NOMEM;
    memcpy(ctx->pass, zKey, nKey);
    ctx->pass_sz = nKey;

    /* read the first 16 bytes directly off the database file. This is the salt. */
    sqlite3_file *fd = sqlite3Pager_get_fd(pPager);
    if(fd == NULL || sqlite3OsRead(fd, ctx->salt, 16, 0) != SQLITE_OK) {
      /* if unable to read the bytes, generate random salt */
      RAND_pseudo_bytes(ctx->salt, FILE_HEADER_SZ);
    }
    
    codec_prepare_key(db, zKey, nKey, ctx->salt, FILE_HEADER_SZ, ctx->key, &prepared_key_sz);
    assert(prepared_key_sz == ctx->key_sz);
    
    sqlite3BtreeSetPageSize(ctx->pBt, sqlite3BtreeGetPageSize(ctx->pBt), ctx->iv_sz, 0);
    sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), sqlite3Codec, (void *) ctx);
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

int sqlite3FreeCodecArg(void *pCodecArg) {
  codec_ctx *ctx = (codec_ctx *) pCodecArg;
  if(pCodecArg == NULL) return SQLITE_OK;
  
  if(ctx->key) {
    memset(ctx->key, 0, ctx->key_sz);
    sqlite3_free(ctx->key);
  }

  if(ctx->rekey) {
    memset(ctx->rekey, 0, ctx->key_sz);
    sqlite3_free(ctx->rekey);
  }
  
  if(ctx->buffer) {
    memset(ctx->buffer, 0, sqlite3BtreeGetPageSize(ctx->pBt));
    sqlite3_free(ctx->buffer);
  }
  
  if(ctx->salt) {
    memset(ctx->salt, 0, FILE_HEADER_SZ);
    sqlite3_free(ctx->salt);
  }

  if(ctx->pass) {
    memset(ctx->pass, 0, ctx->pass_sz);
    sqlite3_free(ctx->pass);
  }
  
  memset(ctx, 0, sizeof(codec_ctx));
  sqlite3_free(ctx);
  return SQLITE_OK;
}

void sqlite3_activate_see(const char* in) {
  /* do nothing, security enhancements are always active */
}

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
  /* attach key if db and pKey are not null and nKey is > 0 */
  if(db && pKey && nKey) {
    int i;
    for(i=0; i<db->nDb; i++){
      sqlite3CodecAttach(db, i, pKey, nKey);
    }
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

/* sqlite3_rekey 
** Given a database, this will reencrypt the database using a new key.
** There are two possible modes of operation. The first is rekeying
** an existing database that was not previously encrypted. The second
** is to change the key on an existing database.
** 
** The proposed logic for this function follows:
** 1. Determine if there is already a key present
** 2. If there is NOT already a key present, create one and attach a codec (key would be null)
** 3. Initialize a ctx->rekey parameter of the codec
** 
** Note: this will require modifications to the sqlite3Codec to support rekey
**
*/
int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey) {
  if(db && pKey && nKey) {
    int i, prepared_key_sz;
    int key_sz =  EVP_CIPHER_key_length(CIPHER);
    void *key = sqlite3Malloc(key_sz);
    if(key == NULL) return SQLITE_NOMEM;
    
    for(i=0; i<db->nDb; i++){
      struct Db *pDb = &db->aDb[i];
      if(pDb->pBt) {
        codec_ctx *ctx;
        int rc;
        Pgno page_count, pgno;
        PgHdr *page;
        Pager *pPager = pDb->pBt->pBt->pPager;
 
        sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
        
        if(ctx == NULL) { 
          /* there was no codec attached to this database,so attach one now with a null password */
          char *error;
          db->nextPagesize =  sqlite3BtreeGetPageSize(pDb->pBt);
          pDb->pBt->pBt->pageSizeFixed = 0; /* required for sqlite3BtreeSetPageSize to modify pagesize setting */
          sqlite3BtreeSetPageSize(pDb->pBt, db->nextPagesize, EVP_CIPHER_iv_length(CIPHER), 0);
          sqlite3RunVacuum(&error, db);
          sqlite3CodecAttach(db, i, pKey, nKey);
          sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
          /* prepare this setup as if it had already been initialized */
          RAND_pseudo_bytes(ctx->salt, FILE_HEADER_SZ);
          ctx->rekey_plaintext = 1;
        }
        
        codec_prepare_key(db, pKey, nKey, ctx->salt, FILE_HEADER_SZ, key, &prepared_key_sz);  
        assert(prepared_key_sz == key_sz);
        
        ctx->rekey = key; /* set rekey to new key data - note that ctx->key is original encryption key */
      
        /* do stuff here to rewrite the database 
        ** 1. Create a transaction on the database
        ** 2. Iterate through each page, reading it and then writing it.
        ** 3. If that goes ok then commit and put ctx->rekey into ctx->key
        **    note: don't deallocate rekey since it may be used in a subsequent iteration 
        */
        rc = sqlite3BtreeBeginTrans(pDb->pBt, 1); /* begin write transaction */
        rc = sqlite3PagerPagecount(pPager, &page_count);
        for(pgno = 1; rc == SQLITE_OK && pgno <= page_count; pgno++) { /* pgno's start at 1 see pager.c:pagerAcquire */
          if(!sqlite3pager_is_mj_pgno(pPager, pgno)) { /* skip this page (see pager.c:pagerAcquire for reasoning) */
            rc = sqlite3PagerGet(pPager, pgno, &page);
            if(rc == SQLITE_OK) { /* write page see pager_incr_changecounter for example */
              rc = sqlite3PagerWrite(page);
              //printf("sqlite3PagerWrite(%d)\n", pgno);
              if(rc == SQLITE_OK) {
                sqlite3PagerUnref(page);
              } 
            } 
          } 
        }

        /* if commit was successful commit and copy the rekey data to current key, else rollback to release locks */
        if(rc == SQLITE_OK) { 
          rc = sqlite3BtreeCommit(pDb->pBt); 
          memcpy(ctx->key, ctx->rekey, key_sz); 
          if(ctx->pass) {
            memset(ctx->pass, 0, ctx->pass_sz);
            sqlite3_free(ctx->pass);
          }
          ctx->pass = sqlite3Malloc(nKey);
          if(ctx->pass == NULL) return SQLITE_NOMEM;
          memcpy(ctx->pass, pKey, nKey);
          ctx->pass_sz = nKey;

        } else {
          printf("error\n");
          sqlite3BtreeRollback(pDb->pBt);
        }

        /* cleanup rekey data, make sure to overwrite rekey_plaintext or read errors will ensue */
        ctx->rekey = NULL; 
        ctx->rekey_plaintext = 0;
      }
    }
    
    /* clear and free temporary key data */
    memset(key, 0, key_sz); 
    sqlite3_free(key);
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

void sqlite3CodecGetKey(sqlite3* db, int nDb, void **zKey, int *nKey) {
  codec_ctx *ctx;
  struct Db *pDb = &db->aDb[nDb];
  
  if( pDb->pBt ) {
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);

    /* if the codec has an attached codec_context user the raw key data */
    if(ctx) {
      *zKey = ctx->pass;
      *nKey = ctx->pass_sz;
    } else {
      *zKey = 0;
      *nKey = 0;  
    }
  }
  
}


/* END CRYPTO */
#endif
