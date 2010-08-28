/* 
** SQLCipher
** crypto.c developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** Copyright (c) 2009, ZETETIC LLC
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

#ifdef CODEC_DEBUG
#define CODEC_TRACE(X)  {printf X;fflush(stdout);}
#else
#define CODEC_TRACE(X)
#endif

void sqlite3FreeCodecArg(void *pCodecArg);

typedef struct {
  int derive_key;
  EVP_CIPHER *evp_cipher;
  int kdf_iter;
  int key_sz;
  int iv_sz;
  int pass_sz;
  unsigned char *key;
  char *pass;
} cipher_ctx;

typedef struct {
  int kdf_salt_sz;
  int mode_rekey;
  unsigned char *kdf_salt;
  unsigned char *buffer;
  Btree *pBt;
  cipher_ctx *read_ctx;
  cipher_ctx *write_ctx;
} codec_ctx;

static void activate_openssl() {
  sqlite3_mutex_enter(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
  if(EVP_get_cipherbyname(CIPHER) == NULL) {
    OpenSSL_add_all_algorithms();
  } 
  sqlite3_mutex_leave(sqlite3MutexAlloc(SQLITE_MUTEX_STATIC_MASTER));
}

/*
**  Simple routines for converting hex char strings to binary data
 */
static int cipher_hex2int(char c) {
  return (c>='0' && c<='9') ? (c)-'0' :
         (c>='A' && c<='F') ? (c)-'A'+10 :
         (c>='a' && c<='f') ? (c)-'a'+10 : 0;
}

static void cipher_hex2bin(const char *hex, int sz, unsigned char *out){
  int i;
  for(i = 0; i < sz; i += 2){
    out[i/2] = (cipher_hex2int(hex[i])<<4) | cipher_hex2int(hex[i+1]);
  }
}


/**
  * Free and wipe memory
  * If ptr is not null memory will be freed. 
  * If sz is greater than zero, the memory will be overwritten with zero before it is freed
  */
static void codec_free(void *ptr, int sz) {
  if(ptr) {
    if(sz > 0) memset(ptr, 0, sz); // FIXME - require buffer size
    sqlite3_free(ptr);
  }
}

/**
  * Set the raw password / key data for a cipher context
  * 
  * returns SQLITE_OK if assignment was successfull
  * returns SQLITE_NOMEM if an error occured allocating memory
  * returns SQLITE_ERROR if the key couldn't be set because the pass was null or size was zero
  */
static int cipher_ctx_set_pass(cipher_ctx *ctx, const void *zKey, int nKey) {
  codec_free(ctx->pass, ctx->pass_sz);
  ctx->pass_sz = nKey;
  if(zKey && nKey) {
    ctx->pass = sqlite3Malloc(nKey);
    if(ctx->pass == NULL) return SQLITE_NOMEM;
    memcpy(ctx->pass, zKey, nKey);
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

/**
  * Initialize a a new cipher_ctx struct. This function will allocate memory
  * for the cipher context and for the key
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int cipher_ctx_init(cipher_ctx **iCtx) {
  cipher_ctx *ctx;
  *iCtx = sqlite3Malloc(sizeof(cipher_ctx));
  ctx = *iCtx;
  if(ctx == NULL) return SQLITE_NOMEM;
  memset(ctx, 0, sizeof(cipher_ctx)); 
  ctx->key = sqlite3Malloc(EVP_MAX_KEY_LENGTH);
  if(ctx->key == NULL) return SQLITE_NOMEM;
  return SQLITE_OK;
}

/**
  * Free and wipe memory associated with a cipher_ctx
  */
static void cipher_ctx_free(cipher_ctx **iCtx) {
  cipher_ctx *ctx = *iCtx;
  CODEC_TRACE(("cipher_ctx_free: entered iCtx=%d\n", iCtx));
  codec_free(ctx->key, ctx->key_sz);
  codec_free(ctx->pass, ctx->pass_sz);
  codec_free(ctx, sizeof(cipher_ctx)); 
}

/**
  * Copy one cipher_ctx to another. For instance, assuming that read_ctx is a 
  * fully initialized context, you could copy it to write_ctx and all yet data
  * and pass information across
  *
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if an error occured allocating memory
  */
static int cipher_ctx_copy(cipher_ctx *target, cipher_ctx *source) {
  void *key = target->key; 
  CODEC_TRACE(("cipher_ctx_copy: entered target=%d, source=%d\n", target, source));
  codec_free(target->pass, target->pass_sz); 
  memcpy(target, source, sizeof(cipher_ctx));
  
  target->key = key; //restore pointer to previously allocated key data
  memcpy(target->key, source->key, EVP_MAX_KEY_LENGTH);
  target->pass = sqlite3Malloc(source->pass_sz);
  if(target->pass == NULL) return SQLITE_NOMEM;
  memcpy(target->pass, source->pass, source->pass_sz);
  return SQLITE_OK;
}

/**
  * Compare one cipher_ctx to another.
  *
  * returns 0 if all the parameters (except the derived key data) are the same
  * returns 1 otherwise
  */
static int cipher_ctx_cmp(cipher_ctx *c1, cipher_ctx *c2) {
  CODEC_TRACE(("cipher_ctx_cmp: entered c1=%d c2=%d\n", c1, c2));

  if(
    c1->evp_cipher == c2->evp_cipher
    && c1->iv_sz == c2->iv_sz
    && c1->kdf_iter == c2->kdf_iter
    && c1->key_sz == c2->key_sz
    && c1->pass_sz == c2->pass_sz
    && (
      c1->pass == c2->pass
      || !memcmp(c1->pass, c2->pass, c1->pass_sz)
    ) 
  ) return 0;
  return 1;
}

/**
  * Free and wipe memory associated with a cipher_ctx, including the allocated
  * read_ctx and write_ctx.
  */
static void codec_ctx_free(codec_ctx **iCtx) {
  codec_ctx *ctx = *iCtx;
  CODEC_TRACE(("codec_ctx_free: entered iCtx=%d\n", iCtx));
  codec_free(ctx->kdf_salt, ctx->kdf_salt_sz);
  codec_free(ctx->buffer, 0);
  cipher_ctx_free(&ctx->read_ctx);
  cipher_ctx_free(&ctx->write_ctx);
  codec_free(ctx, sizeof(codec_ctx)); 
}

/**
  * Derive an encryption key for a cipher contex key based on the raw password.
  *
  * If the raw key data is formated as x'hex' and there are exactly enough hex chars to fill
  * the key space (i.e 64 hex chars for a 256 bit key) then the key data will be used directly. 
  * 
  * Otherwise, a key data will be derived using PBKDF2
  * 
  * returns SQLITE_OK if initialization was successful
  * returns SQLITE_NOMEM if the key could't be derived (for instance if pass is NULL or pass_sz is 0)
  */
static int codec_key_derive(codec_ctx *ctx, cipher_ctx *c_ctx) { 
  CODEC_TRACE(("codec_key_derive: entered c_ctx->pass=%s, c_ctx->pass_sz=%d ctx->kdf_salt=%d ctx->kdf_salt_sz=%d c_ctx->kdf_iter=%d c_ctx->key_sz=%d\n", 
    c_ctx->pass, c_ctx->pass_sz, ctx->kdf_salt, ctx->kdf_salt_sz, c_ctx->kdf_iter, c_ctx->key_sz));

  if(c_ctx->pass && c_ctx->pass_sz) { // if pass is not null
    if (c_ctx->pass_sz == ((c_ctx->key_sz*2)+3) && sqlite3StrNICmp(c_ctx->pass ,"x'", 2) == 0) { 
      int n = c_ctx->pass_sz - 3; /* adjust for leading x' and tailing ' */
      const char *z = c_ctx->pass + 2; /* adjust lead offset of x' */ 
      CODEC_TRACE(("codec_key_derive: deriving key from hex\n")); 
      cipher_hex2bin(z, n, c_ctx->key);
    } else { 
      CODEC_TRACE(("codec_key_derive: deriving key using PBKDF2\n")); 
      PKCS5_PBKDF2_HMAC_SHA1(c_ctx->pass, c_ctx->pass_sz, ctx->kdf_salt, ctx->kdf_salt_sz, c_ctx->kdf_iter, c_ctx->key_sz, c_ctx->key);
    }
    return SQLITE_OK;
  };
  return SQLITE_ERROR;
}

/*
 * ctx - codec context
 * pgno - page number in database
 * size - size in bytes of input and output buffers
 * mode - 1 to encrypt, 0 to decrypt
 * in - pointer to input bytes
 * out - pouter to output bytes
 */
static int codec_cipher(cipher_ctx *ctx, Pgno pgno, int mode, int size, unsigned char *in, unsigned char *out) {
  EVP_CIPHER_CTX ectx;
  unsigned char *iv;
  int tmp_csz, csz;

  CODEC_TRACE(("codec_cipher:entered pgno=%d, mode=%d, size=%d\n", pgno, mode, size));

  /* just copy raw data from in to out when key size is 0
   * i.e. during a rekey of a plaintext database */ 
  if(ctx->key_sz == 0) {
    memcpy(out, in, size);
    return SQLITE_OK;
  } 

  // FIXME - only run if using an IV
  size = size - ctx->iv_sz; /* adjust size to useable size and memset reserve at end of page */
  iv = out + size;
  if(mode == CIPHER_ENCRYPT) {
    RAND_pseudo_bytes(iv, ctx->iv_sz);
  } else {
    memcpy(iv, in+size, ctx->iv_sz);
  } 
  
  EVP_CipherInit(&ectx, ctx->evp_cipher, NULL, NULL, mode);
  EVP_CIPHER_CTX_set_padding(&ectx, 0);
  EVP_CipherInit(&ectx, NULL, ctx->key, iv, mode);
  EVP_CipherUpdate(&ectx, out, &tmp_csz, in, size);
  csz = tmp_csz;  
  out += tmp_csz;
  EVP_CipherFinal(&ectx, out, &tmp_csz);
  csz += tmp_csz;
  EVP_CIPHER_CTX_cleanup(&ectx);
  assert(size == csz);

  return SQLITE_OK;
}

int codec_set_kdf_iter(sqlite3* db, int nDb, int kdf_iter, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_kdf_iter: entered db=%d nDb=%d kdf_iter=%d for_ctx=%d\n", db, nDb, kdf_iter, for_ctx));

  if(pDb->pBt) {
    codec_ctx *ctx;
    cipher_ctx *c_ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;

    c_ctx->kdf_iter = kdf_iter;
    c_ctx->derive_key = 1;

    if(for_ctx == 2) cipher_ctx_copy( for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx); 
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

/**
  * 
  * when for_ctx == 0 then it will change for read
  * when for_ctx == 1 then it will change for write
  * when for_ctx == 2 then it will change for both
  */
int codec_set_cipher_name(sqlite3* db, int nDb, const char *cipher_name, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_cipher_name: entered db=%d nDb=%d cipher_name=%s for_ctx=%d\n", db, nDb, cipher_name, for_ctx));

  if(pDb->pBt) {
    codec_ctx *ctx;
    cipher_ctx *c_ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;

    c_ctx->evp_cipher = (EVP_CIPHER *) EVP_get_cipherbyname(cipher_name);
    c_ctx->key_sz = EVP_CIPHER_key_length(c_ctx->evp_cipher);
    c_ctx->iv_sz = EVP_CIPHER_iv_length(c_ctx->evp_cipher);
    c_ctx->derive_key = 1;

    if(for_ctx == 2) cipher_ctx_copy( for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx); 
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

int codec_set_pass_key(sqlite3* db, int nDb, const void *zKey, int nKey, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_pass_key: entered db=%d nDb=%d cipher_name=%s nKey=%d for_ctx=%d\n", db, nDb, zKey, nKey, for_ctx));
  if(pDb->pBt) {
    codec_ctx *ctx;
    cipher_ctx *c_ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    c_ctx = for_ctx ? ctx->write_ctx : ctx->read_ctx;
  
    cipher_ctx_set_pass(c_ctx, zKey, nKey);
    c_ctx->derive_key = 1;

    if(for_ctx == 2) cipher_ctx_copy( for_ctx ? ctx->read_ctx : ctx->write_ctx, c_ctx); 
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
} 

/*
 * sqlite3Codec can be called in multiple modes.
 * encrypt mode - expected to return a pointer to the 
 *   encrypted data without altering pData.
 * decrypt mode - expected to return a pointer to pData, with
 *   the data decrypted in the input buffer
 */
void* sqlite3Codec(void *iCtx, void *data, Pgno pgno, int mode) {
  codec_ctx *ctx = (codec_ctx *) iCtx;
  int pg_sz = sqlite3BtreeGetPageSize(ctx->pBt);
  int offset = 0;
  unsigned char *pData = (unsigned char *) data;
 
  CODEC_TRACE(("sqlite3Codec: entered pgno=%d, mode=%d, ctx->mode_rekey=%d, pg_sz=%d\n", pgno, mode, ctx->mode_rekey, pg_sz));

  /* derive key on first use if necessary */
  if(ctx->read_ctx->derive_key) {
    codec_key_derive(ctx, ctx->read_ctx);
    ctx->read_ctx->derive_key = 0;
  }

  if(ctx->write_ctx->derive_key) {
    if(cipher_ctx_cmp(ctx->write_ctx, ctx->read_ctx) == 0) {
      cipher_ctx_copy(ctx->write_ctx, ctx->read_ctx); // the relevant parameters are the same, just copy read key
    } else {
      codec_key_derive(ctx, ctx->write_ctx);
      ctx->write_ctx->derive_key = 0;
    }
  }


  if(pgno == 1) offset = FILE_HEADER_SZ; /* adjust starting pointers in data page for header offset on first page*/

  CODEC_TRACE(("sqlite3Codec: switch mode=%d offset=%d\n",  mode, offset));
  switch(mode) {
    case 0: /* decrypt */
    case 2:
    case 3:
      if(pgno == 1) memcpy(ctx->buffer, SQLITE_FILE_HEADER, FILE_HEADER_SZ); /* copy file header to the first 16 bytes of the page */ 
      codec_cipher(ctx->read_ctx, pgno, CIPHER_DECRYPT, pg_sz - offset, pData + offset, ctx->buffer + offset);
      memcpy(pData, ctx->buffer, pg_sz); /* copy buffer data back to pData and return */
      return pData;
      break;
    case 6: /* encrypt */
      if(pgno == 1) memcpy(ctx->buffer, ctx->kdf_salt, FILE_HEADER_SZ); /* copy salt to output buffer */ 
      codec_cipher(ctx->write_ctx, pgno, CIPHER_ENCRYPT, pg_sz - offset, pData + offset, ctx->buffer + offset);
      return ctx->buffer; /* return persistent buffer data, pData remains intact */
      break;
    case 7:
      if(pgno == 1) memcpy(ctx->buffer, ctx->kdf_salt, FILE_HEADER_SZ); /* copy salt to output buffer */ 
      codec_cipher(ctx->read_ctx, pgno, CIPHER_ENCRYPT, pg_sz - offset, pData + offset, ctx->buffer + offset);
      return ctx->buffer; /* return persistent buffer data, pData remains intact */
      break;
    default:
      return pData;
      break;
  }
}


int sqlite3CodecAttach(sqlite3* db, int nDb, const void *zKey, int nKey) {
  struct Db *pDb = &db->aDb[nDb];

  CODEC_TRACE(("sqlite3CodecAttach: entered nDb=%d zKey=%s, nKey=%d\n", nDb, zKey, nKey));
  activate_openssl();
  
  if(nKey && zKey && pDb->pBt) {
    codec_ctx *ctx;
    int rc;
    Pager *pPager = pDb->pBt->pBt->pPager;
    sqlite3_file *fd;

    ctx = sqlite3Malloc(sizeof(codec_ctx));
    if(ctx == NULL) return SQLITE_NOMEM;
    memset(ctx, 0, sizeof(codec_ctx)); /* initialize all pointers and values to 0 */

    ctx->pBt = pDb->pBt; /* assign pointer to database btree structure */

    if((rc = cipher_ctx_init(&ctx->read_ctx)) != SQLITE_OK) return rc; 
    if((rc = cipher_ctx_init(&ctx->write_ctx)) != SQLITE_OK) return rc; 
    
    /* pre-allocate a page buffer of PageSize bytes. This will
       be used as a persistent buffer for encryption and decryption 
       operations to avoid overhead of multiple memory allocations*/
    ctx->buffer = sqlite3Malloc(sqlite3BtreeGetPageSize(ctx->pBt));
    if(ctx->buffer == NULL) return SQLITE_NOMEM;
     
    /* allocate space for salt data. Then read the first 16 bytes 
       directly off the database file. This is the salt for the
       key derivation function. If we get a short read allocate
       a new random salt value */
    ctx->kdf_salt_sz = FILE_HEADER_SZ;
    ctx->kdf_salt = sqlite3Malloc(ctx->kdf_salt_sz);
    if(ctx->kdf_salt == NULL) return SQLITE_NOMEM;

    fd = sqlite3Pager_get_fd(pPager);
    if(fd == NULL || sqlite3OsRead(fd, ctx->kdf_salt, FILE_HEADER_SZ, 0) != SQLITE_OK) {
      /* if unable to read the bytes, generate random salt */
      RAND_pseudo_bytes(ctx->kdf_salt, FILE_HEADER_SZ);
    }

    sqlite3pager_sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), sqlite3Codec, NULL, sqlite3FreeCodecArg, (void *) ctx);

    codec_set_cipher_name(db, nDb, CIPHER, 0);
    codec_set_kdf_iter(db, nDb, PBKDF2_ITER, 0);
    codec_set_pass_key(db, nDb, zKey, nKey, 0);
    cipher_ctx_copy(ctx->write_ctx, ctx->read_ctx);
    
    sqlite3BtreeSetPageSize(ctx->pBt, sqlite3BtreeGetPageSize(ctx->pBt), EVP_MAX_IV_LENGTH, 0);
  }
  return SQLITE_OK;
}

void sqlite3FreeCodecArg(void *pCodecArg) {
  codec_ctx *ctx = (codec_ctx *) pCodecArg;
  if(pCodecArg == NULL) return;
  codec_ctx_free(&ctx); // wipe and free allocated memory for the context 
}

void sqlite3_activate_see(const char* in) {
  /* do nothing, security enhancements are always active */
}

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
  CODEC_TRACE(("sqlite3_key: entered db=%d pKey=%s nKey=%d\n", db, pKey, nKey));
  /* attach key if db and pKey are not null and nKey is > 0 */
  if(db && pKey && nKey) {
    sqlite3CodecAttach(db, 0, pKey, nKey); // operate only on the main db 
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
  CODEC_TRACE(("sqlite3_rekey: entered db=%d pKey=%s, nKey=%d\n", db, pKey, nKey));
  activate_openssl();
  if(db && pKey && nKey) {
    struct Db *pDb = &db->aDb[0];
    CODEC_TRACE(("sqlite3_rekey: database pDb=%d\n", pDb));
    if(pDb->pBt) {
      codec_ctx *ctx;
      int rc, page_count;
      Pgno pgno;
      PgHdr *page;
      Pager *pPager = pDb->pBt->pBt->pPager;

      sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
     
      if(ctx == NULL) { 
        CODEC_TRACE(("sqlite3_rekey: no codec attached to db, attaching now\n"));
        /* there was no codec attached to this database,so attach one now with a null password */
        sqlite3CodecAttach(db, 0, pKey, nKey);
        sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
        
        /* prepare this setup as if it had already been initialized */
        RAND_pseudo_bytes(ctx->kdf_salt, ctx->kdf_salt_sz);
        ctx->read_ctx->key_sz = ctx->read_ctx->iv_sz =  ctx->read_ctx->pass_sz = 0;
      }

      if(ctx->read_ctx->iv_sz != ctx->write_ctx->iv_sz) {
        char *error;
        CODEC_TRACE(("sqlite3_rekey: updating page size for iv_sz change from %d to %d\n", ctx->read_ctx->iv_sz, ctx->write_ctx->iv_sz));
        db->nextPagesize = sqlite3BtreeGetPageSize(pDb->pBt);
        pDb->pBt->pBt->pageSizeFixed = 0; /* required for sqlite3BtreeSetPageSize to modify pagesize setting */
        sqlite3BtreeSetPageSize(pDb->pBt, db->nextPagesize, EVP_MAX_IV_LENGTH, 0);
        sqlite3RunVacuum(&error, db);
      }

      codec_set_pass_key(db, 0, pKey, nKey, 1);
      ctx->mode_rekey = 1; 
    
      /* do stuff here to rewrite the database 
      ** 1. Create a transaction on the database
      ** 2. Iterate through each page, reading it and then writing it.
      ** 3. If that goes ok then commit and put ctx->rekey into ctx->key
      **    note: don't deallocate rekey since it may be used in a subsequent iteration 
      */
      rc = sqlite3BtreeBeginTrans(pDb->pBt, 1); /* begin write transaction */
      sqlite3PagerPagecount(pPager, &page_count);
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
        CODEC_TRACE(("sqlite3_rekey: committing\n"));
        db->nextPagesize = sqlite3BtreeGetPageSize(pDb->pBt);
        rc = sqlite3BtreeCommit(pDb->pBt); 
        cipher_ctx_copy(ctx->read_ctx, ctx->write_ctx);
      } else {
        CODEC_TRACE(("sqlite3_rekey: rollback\n"));
        sqlite3BtreeRollback(pDb->pBt);
      }

      ctx->mode_rekey = 0;
    }
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

void sqlite3CodecGetKey(sqlite3* db, int nDb, void **zKey, int *nKey) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("sqlite3CodecGetKey: entered db=%d, nDb=%d\n", db, nDb));
  
  if( pDb->pBt ) {
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);

    if(ctx) { /* if the codec has an attached codec_context user the raw key data */
      *zKey = ctx->read_ctx->pass;
      *nKey = ctx->read_ctx->pass_sz;
    } else {
      *zKey = NULL;
      *nKey = 0;
    }
  }
}


/* END CRYPTO */
#endif
