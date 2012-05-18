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

/* Generate code to return a string value */
void codec_vdbe_return_static_string(Parse *pParse, const char *zLabel, const char *value){
  Vdbe *v = sqlite3GetVdbe(pParse);
  sqlite3VdbeSetNumCols(v, 1);
  sqlite3VdbeSetColName(v, 0, COLNAME_NAME, zLabel, SQLITE_STATIC);
  sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, value, 0);
  sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
}

int codec_set_kdf_iter(sqlite3* db, int nDb, int kdf_iter, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_kdf_iter: entered db=%p nDb=%d kdf_iter=%d for_ctx=%d\n", db, nDb, kdf_iter, for_ctx));

  if(pDb->pBt) {
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    if(ctx) return sqlcipher_codec_ctx_set_kdf_iter(ctx, kdf_iter, for_ctx);
  }
  return SQLITE_ERROR;
}

int codec_set_fast_kdf_iter(sqlite3* db, int nDb, int kdf_iter, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_kdf_iter: entered db=%p nDb=%d kdf_iter=%d for_ctx=%d\n", db, nDb, kdf_iter, for_ctx));

  if(pDb->pBt) {
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    if(ctx) return sqlcipher_codec_ctx_set_fast_kdf_iter(ctx, kdf_iter, for_ctx);
  }
  return SQLITE_ERROR;
}

static int codec_set_btree_to_codec_pagesize(sqlite3 *db, Db *pDb, codec_ctx *ctx) {
  int rc, page_sz, reserve_sz; 

  page_sz = sqlcipher_codec_ctx_get_pagesize(ctx);
  reserve_sz = sqlcipher_codec_ctx_get_reservesize(ctx);

  sqlite3_mutex_enter(db->mutex);
  db->nextPagesize = page_sz; 

  /* before forcing the page size we need to unset the BTS_PAGESIZE_FIXED flag, else  
     sqliteBtreeSetPageSize will block the change  */
  pDb->pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;
  CODEC_TRACE(("codec_set_btree_to_codec_pagesize: sqlite3BtreeSetPageSize() size=%d reserve=%d\n", page_sz, reserve_sz));
  rc = sqlite3BtreeSetPageSize(pDb->pBt, page_sz, reserve_sz, 0);
  sqlite3_mutex_leave(db->mutex);
  return rc;
}

void codec_set_default_use_hmac(int use) {
  sqlcipher_set_default_use_hmac(use);
}

int codec_set_use_hmac(sqlite3* db, int nDb, int use) {
  struct Db *pDb = &db->aDb[nDb];

  CODEC_TRACE(("codec_set_use_hmac: entered db=%p nDb=%d use=%d\n", db, nDb, use));

  if(pDb->pBt) {
    int rc;
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    if(ctx) {
      rc = sqlcipher_codec_ctx_set_use_hmac(ctx, use);
      if(rc != SQLITE_OK) return rc;
      /* since the use of hmac has changed, the page size may also change */
      return codec_set_btree_to_codec_pagesize(db, pDb, ctx);
    }
  }
  return SQLITE_ERROR;
}

int codec_set_page_size(sqlite3* db, int nDb, int size) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_page_size: entered db=%p nDb=%d size=%d\n", db, nDb, size));

  if(pDb->pBt) {
    int rc;
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);

    if(ctx) {
      rc = sqlcipher_codec_ctx_set_pagesize(ctx, size);
      if(rc != SQLITE_OK) return rc;
      return codec_set_btree_to_codec_pagesize(db, pDb, ctx);
    }
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
  CODEC_TRACE(("codec_set_cipher_name: entered db=%p nDb=%d cipher_name=%s for_ctx=%d\n", db, nDb, cipher_name, for_ctx));

  if(pDb->pBt) {
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    if(ctx) return sqlcipher_codec_ctx_set_cipher(ctx, cipher_name, for_ctx);
  }
  return SQLITE_ERROR;
}

int codec_set_pass_key(sqlite3* db, int nDb, const void *zKey, int nKey, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("codec_set_pass_key: entered db=%p nDb=%d zKey=%s nKey=%d for_ctx=%d\n", db, nDb, (char *)zKey, nKey, for_ctx));
  if(pDb->pBt) {
    codec_ctx *ctx;
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    if(ctx) return sqlcipher_codec_ctx_set_pass(ctx, zKey, nKey, for_ctx);
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

  /* call to derive keys if not present yet */
  if((rc = sqlcipher_codec_key_derive(ctx)) != SQLITE_OK) {
   sqlcipher_codec_ctx_set_error(ctx, rc); 
   return NULL;
  }

  if(pgno == 1) offset = FILE_HEADER_SZ; /* adjust starting pointers in data page for header offset on first page*/

  CODEC_TRACE(("sqlite3Codec: switch mode=%d offset=%d\n",  mode, offset));
  switch(mode) {
    case 0: /* decrypt */
    case 2:
    case 3:
      if(pgno == 1) memcpy(buffer, SQLITE_FILE_HEADER, FILE_HEADER_SZ); /* copy file header to the first 16 bytes of the page */ 
      rc = sqlcipher_page_cipher(ctx, CIPHER_READ_CTX, pgno, CIPHER_DECRYPT, page_sz - offset, pData + offset, (unsigned char*)buffer + offset);
      if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      memcpy(pData, buffer, page_sz); /* copy buffer data back to pData and return */
      return pData;
      break;
    case 6: /* encrypt */
      if(pgno == 1) memcpy(buffer, kdf_salt, FILE_HEADER_SZ); /* copy salt to output buffer */ 
      rc = sqlcipher_page_cipher(ctx, CIPHER_WRITE_CTX, pgno, CIPHER_ENCRYPT, page_sz - offset, pData + offset, (unsigned char*)buffer + offset);
      if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      return buffer; /* return persistent buffer data, pData remains intact */
      break;
    case 7:
      if(pgno == 1) memcpy(buffer, kdf_salt, FILE_HEADER_SZ); /* copy salt to output buffer */ 
      rc = sqlcipher_page_cipher(ctx, CIPHER_READ_CTX, pgno, CIPHER_ENCRYPT, page_sz - offset, pData + offset, (unsigned char*)buffer + offset);
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

  CODEC_TRACE(("sqlite3CodecAttach: entered nDb=%d zKey=%s, nKey=%d\n", nDb, (char *)zKey, nKey));

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
  CODEC_TRACE(("sqlite3_key: entered db=%p pKey=%s nKey=%d\n", db, (char *)pKey, nKey));
  /* attach key if db and pKey are not null and nKey is > 0 */
  if(db && pKey && nKey) {
    sqlite3CodecAttach(db, 0, pKey, nKey); // operate only on the main db 
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

/* sqlite3_rekey 
** Given a database, this will reencrypt the database using a new key.
** There is only one possible modes of operation - to encrypt a database
** that is already encrpyted. If the database is not already encrypted
** this should do nothing
** The proposed logic for this function follows:
** 1. Determine if the database is already encryptped
** 2. If there is NOT already a key present do nothing
** 3. If there is a key present, re-encrypt the database with the new key
*/
int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey) {
  CODEC_TRACE(("sqlite3_rekey: entered db=%p pKey=%s, nKey=%d\n", db, (char *)pKey, nKey));
  sqlcipher_activate();
  if(db && pKey && nKey) {
    struct Db *pDb = &db->aDb[0];
    CODEC_TRACE(("sqlite3_rekey: database pDb=%p\n", pDb));
    if(pDb->pBt) {
      codec_ctx *ctx;
      int rc, page_count;
      Pgno pgno;
      PgHdr *page;
      Pager *pPager = pDb->pBt->pBt->pPager;

      sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
     
      if(ctx == NULL) { 
        /* there was no codec attached to this database, so this should do nothing! */ 
        CODEC_TRACE(("sqlite3_rekey: no codec attached to db, exiting\n"));
        return SQLITE_OK;
      }

      sqlite3_mutex_enter(db->mutex);

      codec_set_pass_key(db, 0, pKey, nKey, CIPHER_WRITE_CTX);
    
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
        sqlite3BtreeRollback(pDb->pBt, SQLITE_ABORT_ROLLBACK);
      }

      sqlite3_mutex_leave(db->mutex);
    }
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

void sqlite3CodecGetKey(sqlite3* db, int nDb, void **zKey, int *nKey) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE(("sqlite3CodecGetKey: entered db=%p, nDb=%d\n", db, nDb));
  
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
