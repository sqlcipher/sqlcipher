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
#include "sqliteInt.h"
#include "btreeInt.h"
#include "crypto.h"

int codec_set_kdf_iter(sqlite3* db, int nDb, int kdf_iter, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_kdf_iter: entered db=%d nDb=%d kdf_iter=%d for_ctx=%d\n", db, nDb, kdf_iter, for_ctx));

  if(pDb->pBt) {
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    return sqlcipher_codec_ctx_set_kdf_iter(ctx, kdf_iter, for_ctx);
  }
  return SQLITE_ERROR;
}

static int codec_set_btree_to_codec_pagesize(sqlite3 *db, Db *pDb, codec_ctx *ctx) {
  int rc, page_sz, reserve_sz; 

  page_sz = sqlcipher_codec_ctx_get_pagesize(ctx);
  reserve_sz = sqlcipher_codec_ctx_get_reservesize(ctx);

  sqlite3_mutex_enter(db->mutex);
  db->nextPagesize = page_sz; 
  pDb->pBt->pBt->pageSizeFixed = 0; 
  CODEC_TRACE(("codec_set_btree_to_codec_pagesize: sqlite3BtreeSetPageSize() size=%d reserve=%d\n", page_sz, reserve_sz));
  rc = sqlite3BtreeSetPageSize(pDb->pBt, page_sz, reserve_sz, 0);
  sqlite3_mutex_leave(db->mutex);
  return rc;
}

int codec_set_use_hmac(sqlite3* db, int nDb, int use) {
  struct Db *pDb = &db->aDb[nDb];

  CODEC_TRACE(("codec_set_use_hmac: entered db=%d nDb=%d use=%d\n", db, nDb, use));

  if(pDb->pBt) {
    int rc;
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);

    rc = sqlcipher_codec_ctx_set_use_hmac(ctx, use);
    if(rc != SQLITE_OK) return rc;

    /* since the use of hmac has changed, the page size may also change */
    /* Note: before forcing the page size we need to force pageSizeFixed to 0, else  
             sqliteBtreeSetPageSize will block the change  */
    return codec_set_btree_to_codec_pagesize(db, pDb, ctx);
  }
  return SQLITE_ERROR;
}

int codec_set_page_size(sqlite3* db, int nDb, int size) {
  int rc;
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_page_size: entered db=%d nDb=%d size=%d\n", db, nDb, size));

  if(pDb->pBt) {
    int rc, reserve_sz;
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);

    rc = sqlcipher_codec_ctx_set_pagesize(ctx, size);
    if(rc != SQLITE_OK) return rc;

    return codec_set_btree_to_codec_pagesize(db, pDb, ctx);
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
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    return sqlcipher_codec_ctx_set_cipher(ctx, cipher_name, for_ctx);
  }
  return SQLITE_ERROR;
}

int codec_set_pass_key(sqlite3* db, int nDb, const void *zKey, int nKey, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_pass_key: entered db=%d nDb=%d cipher_name=%s nKey=%d for_ctx=%d\n", db, nDb, zKey, nKey, for_ctx));
  if(pDb->pBt) {
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    return sqlcipher_codec_ctx_set_pass(ctx, zKey, nKey, for_ctx);
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
  int offset = 0, rc = 0;
  int page_sz = sqlcipher_codec_ctx_get_pagesize(ctx); 
  unsigned char *pData = (unsigned char *) data;
  void *buffer = sqlcipher_codec_ctx_get_data(ctx);
  void *kdf_salt = sqlcipher_codec_ctx_get_kdf_salt(ctx);
  CODEC_TRACE(("sqlite3Codec: entered pgno=%d, mode=%d, page_sz=%d\n", pgno, mode, page_sz));

  sqlcipher_codec_key_derive(ctx); /* call to derive keys if not present yet */

  if(pgno == 1) offset = FILE_HEADER_SZ; /* adjust starting pointers in data page for header offset on first page*/

  CODEC_TRACE(("sqlite3Codec: switch mode=%d offset=%d\n",  mode, offset));
  switch(mode) {
    case 0: /* decrypt */
    case 2:
    case 3:
      if(pgno == 1) memcpy(buffer, SQLITE_FILE_HEADER, FILE_HEADER_SZ); /* copy file header to the first 16 bytes of the page */ 
      rc = sqlcipher_page_cipher(ctx, CIPHER_READ_CTX, pgno, CIPHER_DECRYPT, page_sz - offset, pData + offset, buffer + offset);
      if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      memcpy(pData, buffer, page_sz); /* copy buffer data back to pData and return */
      return pData;
      break;
    case 6: /* encrypt */
      if(pgno == 1) memcpy(buffer, kdf_salt, FILE_HEADER_SZ); /* copy salt to output buffer */ 
      rc = sqlcipher_page_cipher(ctx, CIPHER_WRITE_CTX, pgno, CIPHER_ENCRYPT, page_sz - offset, pData + offset, buffer + offset);
      if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      return buffer; /* return persistent buffer data, pData remains intact */
      break;
    case 7:
      if(pgno == 1) memcpy(buffer, kdf_salt, FILE_HEADER_SZ); /* copy salt to output buffer */ 
      rc = sqlcipher_page_cipher(ctx, CIPHER_READ_CTX, pgno, CIPHER_ENCRYPT, page_sz - offset, pData + offset, buffer + offset);
      if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      return buffer; /* return persistent buffer data, pData remains intact */
      break;
    default:
      return pData;
      break;
  }
}

void sqlite3FreeCodecArg(void *pCodecArg) {
  codec_ctx *ctx = (codec_ctx *) pCodecArg;
  if(pCodecArg == NULL) return;
  sqlcipher_codec_ctx_free(&ctx); // wipe and free allocated memory for the context 
}

int sqlite3CodecAttach(sqlite3* db, int nDb, const void *zKey, int nKey) {
  struct Db *pDb = &db->aDb[nDb];

  CODEC_TRACE(("sqlite3CodecAttach: entered nDb=%d zKey=%s, nKey=%d\n", nDb, zKey, nKey));

  sqlcipher_activate();

  if(nKey && zKey && pDb->pBt) {
    int rc;
    Pager *pPager = pDb->pBt->pBt->pPager;
    sqlite3_file *fd = sqlite3Pager_get_fd(pPager);
    codec_ctx *ctx;

    /* point the internal codec argument against the contet to be prepared */
    rc = sqlcipher_codec_ctx_init(&ctx, pDb, pDb->pBt->pBt->pPager, fd, zKey, nKey); 

    sqlite3pager_sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), sqlite3Codec, NULL, sqlite3FreeCodecArg, (void *) ctx);

    codec_set_btree_to_codec_pagesize(db, pDb, ctx);

    /* if fd is null, then this is an in-memory database and
       we dont' want to overwrite the AutoVacuum settings
       if not null, then set to the default */
    sqlite3_mutex_enter(db->mutex);
    if(fd != NULL) { 
      sqlite3BtreeSetAutoVacuum(pDb->pBt, SQLITE_DEFAULT_AUTOVACUUM);
    }
    sqlite3_mutex_leave(db->mutex);
  }
  return SQLITE_OK;
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
** 
** Note: this will require modifications to the sqlite3Codec to support rekey
**
*/
int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey) {
  CODEC_TRACE(("sqlite3_rekey: entered db=%d pKey=%s, nKey=%d\n", db, pKey, nKey));
  sqlcipher_activate();
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
      }

      sqlite3_mutex_enter(db->mutex);

      codec_set_pass_key(db, 0, pKey, nKey, 1);
    
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
        rc = sqlite3BtreeCommit(pDb->pBt); 
        sqlcipher_codec_key_copy(ctx, CIPHER_WRITE_CTX);
      } else {
        CODEC_TRACE(("sqlite3_rekey: rollback\n"));
        sqlite3BtreeRollback(pDb->pBt);
      }

      sqlite3_mutex_leave(db->mutex);
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
      sqlcipher_codec_get_pass(ctx, zKey, nKey);
    } else {
      *zKey = NULL;
      *nKey = 0;
    }
  }
}


/* END CRYPTO */
#endif
