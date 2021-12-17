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

#include <assert.h>
#include "sqlcipher.h"
#include "crypto.h"

#ifdef SQLCIPHER_EXT
#include "sqlcipher_ext.h"
#endif

static void codec_vdbe_return_string(Parse *pParse, const char *zLabel, const char *value, int value_type){
  Vdbe *v = sqlite3GetVdbe(pParse);
  sqlite3VdbeSetNumCols(v, 1);
  sqlite3VdbeSetColName(v, 0, COLNAME_NAME, zLabel, SQLITE_STATIC);
  sqlite3VdbeAddOp4(v, OP_String8, 0, 1, 0, value, value_type);
  sqlite3VdbeAddOp2(v, OP_ResultRow, 1, 1);
}

static int codec_set_btree_to_codec_pagesize(sqlite3 *db, Db *pDb, codec_ctx *ctx) {
  int rc, page_sz, reserve_sz; 

  page_sz = sqlcipher_codec_ctx_get_pagesize(ctx);
  reserve_sz = sqlcipher_codec_ctx_get_reservesize(ctx);

  CODEC_TRACE("codec_set_btree_to_codec_pagesize: sqlite3BtreeSetPageSize() size=%d reserve=%d\n", page_sz, reserve_sz);

  CODEC_TRACE_MUTEX("codec_set_btree_to_codec_pagesize: entering database mutex %p\n", db->mutex);
  sqlite3_mutex_enter(db->mutex);
  CODEC_TRACE_MUTEX("codec_set_btree_to_codec_pagesize: entered database mutex %p\n", db->mutex);
  db->nextPagesize = page_sz; 

  /* before forcing the page size we need to unset the BTS_PAGESIZE_FIXED flag, else  
     sqliteBtreeSetPageSize will block the change  */
  pDb->pBt->pBt->btsFlags &= ~BTS_PAGESIZE_FIXED;
  rc = sqlite3BtreeSetPageSize(pDb->pBt, page_sz, reserve_sz, 0);

  CODEC_TRACE("codec_set_btree_to_codec_pagesize: sqlite3BtreeSetPageSize returned %d\n", rc);

  CODEC_TRACE_MUTEX("codec_set_btree_to_codec_pagesize: leaving database mutex %p\n", db->mutex);
  sqlite3_mutex_leave(db->mutex);
  CODEC_TRACE_MUTEX("codec_set_btree_to_codec_pagesize: left database mutex %p\n", db->mutex);

  return rc;
}

static int codec_set_pass_key(sqlite3* db, int nDb, const void *zKey, int nKey, int for_ctx) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE("codec_set_pass_key: entered db=%p nDb=%d zKey=%p nKey=%d for_ctx=%d\n", db, nDb, zKey, nKey, for_ctx);
  if(pDb->pBt) {
    codec_ctx *ctx = (codec_ctx*) sqlite3PagerGetCodec(pDb->pBt->pBt->pPager);

    if(ctx) return sqlcipher_codec_ctx_set_pass(ctx, zKey, nKey, for_ctx);
  }
  return SQLITE_ERROR;
} 

int sqlcipher_codec_pragma(sqlite3* db, int iDb, Parse *pParse, const char *zLeft, const char *zRight) {
  struct Db *pDb = &db->aDb[iDb];
  codec_ctx *ctx = NULL;
  int rc;

  if(pDb->pBt) {
    ctx = (codec_ctx*) sqlite3PagerGetCodec(pDb->pBt->pBt->pPager);
  }

  CODEC_TRACE("sqlcipher_codec_pragma: entered db=%p iDb=%d pParse=%p zLeft=%s zRight=%s ctx=%p\n", db, iDb, pParse, zLeft, zRight, ctx);
  
#ifdef SQLCIPHER_EXT
  if( sqlite3_stricmp(zLeft, "cipher_license")==0 && zRight ){
    char *license_result = sqlite3_mprintf("%d", sqlcipher_license_key(zRight));
    codec_vdbe_return_string(pParse, "cipher_license", license_result, P4_DYNAMIC);
  } else
    if( sqlite3_stricmp(zLeft, "cipher_license")==0 && !zRight ){
      if(ctx) {
        char *license_result = sqlite3_mprintf("%d", ctx
                                               ? sqlcipher_license_key_status(ctx->provider)
                                               : SQLITE_ERROR);
        codec_vdbe_return_string(pParse, "cipher_license", license_result, P4_DYNAMIC);
      }
  } else
#endif
#ifdef SQLCIPHER_TEST
  if( sqlite3_stricmp(zLeft,"cipher_test_on")==0 ){
    if( zRight ) {
      unsigned int flags = sqlcipher_get_test_flags();
      if(sqlite3_stricmp(zRight, "fail_encrypt")==0) {
        flags |= TEST_FAIL_ENCRYPT;
      } else
      if(sqlite3_stricmp(zRight, "fail_decrypt")==0) {
        flags |= TEST_FAIL_DECRYPT;
      } else
      if(sqlite3_stricmp(zRight, "fail_migrate")==0) {
        flags |= TEST_FAIL_MIGRATE;
      }
      sqlcipher_set_test_flags(flags);
    }
  } else
  if( sqlite3_stricmp(zLeft,"cipher_test_off")==0 ){
    if( zRight ) {
      unsigned int flags = sqlcipher_get_test_flags();
      if(sqlite3_stricmp(zRight, "fail_encrypt")==0) {
        flags &= ~TEST_FAIL_ENCRYPT;
      } else
      if(sqlite3_stricmp(zRight, "fail_decrypt")==0) {
        flags &= ~TEST_FAIL_DECRYPT;
      } else
      if(sqlite3_stricmp(zRight, "fail_migrate")==0) {
        flags &= ~TEST_FAIL_MIGRATE;
      }
      sqlcipher_set_test_flags(flags);
    }
  } else
  if( sqlite3_stricmp(zLeft,"cipher_test")==0 ){
    char *flags = sqlite3_mprintf("%u", sqlcipher_get_test_flags());
    codec_vdbe_return_string(pParse, "cipher_test", flags, P4_DYNAMIC);
  }else
  if( sqlite3_stricmp(zLeft,"cipher_test_rand")==0 ){
    if( zRight ) {
      int rand = atoi(zRight);
      sqlcipher_set_test_rand(rand);
    } else {
      char *rand = sqlite3_mprintf("%d", sqlcipher_get_test_rand());
      codec_vdbe_return_string(pParse, "cipher_test_rand", rand, P4_DYNAMIC);
    }
  } else
#endif
  if( sqlite3_stricmp(zLeft, "cipher_fips_status")== 0 && !zRight ){
    if(ctx) {
      char *fips_mode_status = sqlite3_mprintf("%d", sqlcipher_codec_fips_status(ctx));
      codec_vdbe_return_string(pParse, "cipher_fips_status", fips_mode_status, P4_DYNAMIC);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_store_pass")==0 && zRight ) {
    if(ctx) {
      char *deprecation = "PRAGMA cipher_store_pass is deprecated, please remove from use";
      sqlcipher_codec_set_store_pass(ctx, sqlite3GetBoolean(zRight, 1));
      codec_vdbe_return_string(pParse, "cipher_store_pass", deprecation, P4_TRANSIENT);
      sqlite3_log(SQLITE_WARNING, deprecation);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_store_pass")==0 && !zRight ) {
    if(ctx){
      char *store_pass_value = sqlite3_mprintf("%d", sqlcipher_codec_get_store_pass(ctx));
      codec_vdbe_return_string(pParse, "cipher_store_pass", store_pass_value, P4_DYNAMIC);
    }
  }
  if( sqlite3_stricmp(zLeft, "cipher_profile")== 0 && zRight ){
      char *profile_status = sqlite3_mprintf("%d", sqlcipher_cipher_profile(db, zRight));
      codec_vdbe_return_string(pParse, "cipher_profile", profile_status, P4_DYNAMIC);
  } else
  if( sqlite3_stricmp(zLeft, "cipher_add_random")==0 && zRight ){
    if(ctx) {
      char *add_random_status = sqlite3_mprintf("%d", sqlcipher_codec_add_random(ctx, zRight, sqlite3Strlen30(zRight)));
      codec_vdbe_return_string(pParse, "cipher_add_random", add_random_status, P4_DYNAMIC);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_migrate")==0 && !zRight ){
    if(ctx){
      int status = sqlcipher_codec_ctx_migrate(ctx); 
      char *migrate_status = sqlite3_mprintf("%d", status);
      codec_vdbe_return_string(pParse, "cipher_migrate", migrate_status, P4_DYNAMIC);
      if(status != SQLITE_OK) {
        CODEC_TRACE("sqlcipher_codec_pragma: error occurred during cipher_migrate: %d\n", status);
        sqlcipher_codec_ctx_set_error(ctx, status);
      }
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_provider")==0 && !zRight ){
    if(ctx) { codec_vdbe_return_string(pParse, "cipher_provider",
                                              sqlcipher_codec_get_cipher_provider(ctx), P4_TRANSIENT);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_provider_version")==0 && !zRight){
    if(ctx) { codec_vdbe_return_string(pParse, "cipher_provider_version",
                                              sqlcipher_codec_get_provider_version(ctx), P4_TRANSIENT);
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_version")==0 && !zRight ){
    codec_vdbe_return_string(pParse, "cipher_version", sqlcipher_version(), P4_DYNAMIC);
  }else
  if( sqlite3_stricmp(zLeft, "cipher")==0 ){
    if(ctx) {
      if( zRight ) {
        const char* message = "PRAGMA cipher is no longer supported.";
        codec_vdbe_return_string(pParse, "cipher", message, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, message);
      }else {
        codec_vdbe_return_string(pParse, "cipher", sqlcipher_codec_ctx_get_cipher(ctx), P4_TRANSIENT); 
      }
    }
  }else
  if( sqlite3_stricmp(zLeft, "rekey_cipher")==0 && zRight ){
    const char* message = "PRAGMA rekey_cipher is no longer supported.";
    codec_vdbe_return_string(pParse, "rekey_cipher", message, P4_TRANSIENT);
    sqlite3_log(SQLITE_WARNING, message);
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_kdf_iter")==0 ){
    if( zRight ) {
      sqlcipher_set_default_kdf_iter(atoi(zRight)); /* change default KDF iterations */
    } else {
      char *kdf_iter = sqlite3_mprintf("%d", sqlcipher_get_default_kdf_iter());
      codec_vdbe_return_string(pParse, "cipher_default_kdf_iter", kdf_iter, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft, "kdf_iter")==0 ){
    if(ctx) {
      if( zRight ) {
        sqlcipher_codec_ctx_set_kdf_iter(ctx, atoi(zRight)); /* change of RW PBKDF2 iteration */
      } else {
        char *kdf_iter = sqlite3_mprintf("%d", sqlcipher_codec_ctx_get_kdf_iter(ctx));
        codec_vdbe_return_string(pParse, "kdf_iter", kdf_iter, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft, "fast_kdf_iter")==0){
    if(ctx) {
      if( zRight ) {
        char *deprecation = "PRAGMA fast_kdf_iter is deprecated, please remove from use";
        sqlcipher_codec_ctx_set_fast_kdf_iter(ctx, atoi(zRight)); /* change of RW PBKDF2 iteration */
        codec_vdbe_return_string(pParse, "fast_kdf_iter", deprecation, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, deprecation);
      } else {
        char *fast_kdf_iter = sqlite3_mprintf("%d", sqlcipher_codec_ctx_get_fast_kdf_iter(ctx));
        codec_vdbe_return_string(pParse, "fast_kdf_iter", fast_kdf_iter, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft, "rekey_kdf_iter")==0 && zRight ){
    const char* message = "PRAGMA rekey_kdf_iter is no longer supported.";
    codec_vdbe_return_string(pParse, "rekey_kdf_iter", message, P4_TRANSIENT);
    sqlite3_log(SQLITE_WARNING, message);
  }else
  if( sqlite3_stricmp(zLeft,"cipher_page_size")==0 ){
    if(ctx) {
      if( zRight ) {
        int size = atoi(zRight);
        rc = sqlcipher_codec_ctx_set_pagesize(ctx, size);
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      } else {
        char * page_size = sqlite3_mprintf("%d", sqlcipher_codec_ctx_get_pagesize(ctx));
        codec_vdbe_return_string(pParse, "cipher_page_size", page_size, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_page_size")==0 ){
    if( zRight ) {
      sqlcipher_set_default_pagesize(atoi(zRight));
    } else {
      char *default_page_size = sqlite3_mprintf("%d", sqlcipher_get_default_pagesize());
      codec_vdbe_return_string(pParse, "cipher_default_page_size", default_page_size, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_use_hmac")==0 ){
    if( zRight ) {
      sqlcipher_set_default_use_hmac(sqlite3GetBoolean(zRight,1));
    } else {
      char *default_use_hmac = sqlite3_mprintf("%d", sqlcipher_get_default_use_hmac());
      codec_vdbe_return_string(pParse, "cipher_default_use_hmac", default_use_hmac, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_use_hmac")==0 ){
    if(ctx) {
      if( zRight ) {
        rc = sqlcipher_codec_ctx_set_use_hmac(ctx, sqlite3GetBoolean(zRight,1));
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
        /* since the use of hmac has changed, the page size may also change */
        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if(rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, rc);
      } else {
        char *hmac_flag = sqlite3_mprintf("%d", sqlcipher_codec_ctx_get_use_hmac(ctx));
        codec_vdbe_return_string(pParse, "cipher_use_hmac", hmac_flag, P4_DYNAMIC);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_pgno")==0 ){
    if(ctx) {
      if(zRight) {
        char *deprecation = "PRAGMA cipher_hmac_pgno is deprecated, please remove from use";
        /* clear both pgno endian flags */
        if(sqlite3_stricmp(zRight, "le") == 0) {
          sqlcipher_codec_ctx_unset_flag(ctx, CIPHER_FLAG_BE_PGNO);
          sqlcipher_codec_ctx_set_flag(ctx, CIPHER_FLAG_LE_PGNO);
        } else if(sqlite3_stricmp(zRight, "be") == 0) {
          sqlcipher_codec_ctx_unset_flag(ctx, CIPHER_FLAG_LE_PGNO);
          sqlcipher_codec_ctx_set_flag(ctx, CIPHER_FLAG_BE_PGNO);
        } else if(sqlite3_stricmp(zRight, "native") == 0) {
          sqlcipher_codec_ctx_unset_flag(ctx, CIPHER_FLAG_LE_PGNO);
          sqlcipher_codec_ctx_unset_flag(ctx, CIPHER_FLAG_BE_PGNO);
        }
        codec_vdbe_return_string(pParse, "cipher_hmac_pgno", deprecation, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, deprecation);
 
      } else {
        if(sqlcipher_codec_ctx_get_flag(ctx, CIPHER_FLAG_LE_PGNO)) {
          codec_vdbe_return_string(pParse, "cipher_hmac_pgno", "le", P4_TRANSIENT);
        } else if(sqlcipher_codec_ctx_get_flag(ctx, CIPHER_FLAG_BE_PGNO)) {
          codec_vdbe_return_string(pParse, "cipher_hmac_pgno", "be", P4_TRANSIENT);
        } else {
          codec_vdbe_return_string(pParse, "cipher_hmac_pgno", "native", P4_TRANSIENT);
        }
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_salt_mask")==0 ){
    if(ctx) {
      if(zRight) {
        char *deprecation = "PRAGMA cipher_hmac_salt_mask is deprecated, please remove from use";
        if (sqlite3StrNICmp(zRight ,"x'", 2) == 0 && sqlite3Strlen30(zRight) == 5) {
          unsigned char mask = 0;
          const unsigned char *hex = (const unsigned char *)zRight+2;
          cipher_hex2bin(hex,2,&mask);
          sqlcipher_set_hmac_salt_mask(mask);
        }
        codec_vdbe_return_string(pParse, "cipher_hmac_salt_mask", deprecation, P4_TRANSIENT);
        sqlite3_log(SQLITE_WARNING, deprecation);
      } else {
        char *hmac_salt_mask = sqlite3_mprintf("%02x", sqlcipher_get_hmac_salt_mask());
        codec_vdbe_return_string(pParse, "cipher_hmac_salt_mask", hmac_salt_mask, P4_DYNAMIC);
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_plaintext_header_size")==0 ){
    if(ctx) {
      if( zRight ) {
        int size = atoi(zRight);
        /* deliberately ignore result code, if size is invalid it will be set to -1
           and trip the error later in the codec */
        sqlcipher_codec_ctx_set_plaintext_header_size(ctx, size);
      } else {
        char *size = sqlite3_mprintf("%d", sqlcipher_codec_ctx_get_plaintext_header_size(ctx));
        codec_vdbe_return_string(pParse, "cipher_plaintext_header_size", size, P4_DYNAMIC);
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_plaintext_header_size")==0 ){
    if( zRight ) {
      sqlcipher_set_default_plaintext_header_size(atoi(zRight));
    } else {
      char *size = sqlite3_mprintf("%d", sqlcipher_get_default_plaintext_header_size());
      codec_vdbe_return_string(pParse, "cipher_default_plaintext_header_size", size, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_salt")==0 ){
    if(ctx) {
      if(zRight) {
        if (sqlite3StrNICmp(zRight ,"x'", 2) == 0 && sqlite3Strlen30(zRight) == (FILE_HEADER_SZ*2)+3) {
          unsigned char *salt = (unsigned char*) sqlite3_malloc(FILE_HEADER_SZ);
          const unsigned char *hex = (const unsigned char *)zRight+2;
          cipher_hex2bin(hex,FILE_HEADER_SZ*2,salt);
          sqlcipher_codec_ctx_set_kdf_salt(ctx, salt, FILE_HEADER_SZ);
          sqlite3_free(salt);
        }
      } else {
        void *salt;
        char *hexsalt = (char*) sqlite3_malloc((FILE_HEADER_SZ*2)+1);
        if((rc = sqlcipher_codec_ctx_get_kdf_salt(ctx, &salt)) == SQLITE_OK) {
          cipher_bin2hex(salt, FILE_HEADER_SZ, hexsalt);
          codec_vdbe_return_string(pParse, "cipher_salt", hexsalt, P4_DYNAMIC);
        } else {
          sqlite3_free(hexsalt);
          sqlcipher_codec_ctx_set_error(ctx, rc);
        }
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_hmac_algorithm")==0 ){
    if(ctx) {
      if(zRight) {
        rc = SQLITE_ERROR;
        if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA1_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA256_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA256);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA512_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA512);
        }
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
      } else {
        int algorithm = sqlcipher_codec_ctx_get_hmac_algorithm(ctx);
        if(algorithm == SQLCIPHER_HMAC_SHA1) {
          codec_vdbe_return_string(pParse, "cipher_hmac_algorithm", SQLCIPHER_HMAC_SHA1_LABEL, P4_TRANSIENT);
        } else if(algorithm == SQLCIPHER_HMAC_SHA256) {
          codec_vdbe_return_string(pParse, "cipher_hmac_algorithm", SQLCIPHER_HMAC_SHA256_LABEL, P4_TRANSIENT);
        } else if(algorithm == SQLCIPHER_HMAC_SHA512) {
          codec_vdbe_return_string(pParse, "cipher_hmac_algorithm", SQLCIPHER_HMAC_SHA512_LABEL, P4_TRANSIENT);
        }
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_hmac_algorithm")==0 ){
    if(zRight) {
      rc = SQLITE_ERROR;
      if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA1_LABEL) == 0) {
        rc = sqlcipher_set_default_hmac_algorithm(SQLCIPHER_HMAC_SHA1);
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA256_LABEL) == 0) {
        rc = sqlcipher_set_default_hmac_algorithm(SQLCIPHER_HMAC_SHA256);
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_HMAC_SHA512_LABEL) == 0) {
        rc = sqlcipher_set_default_hmac_algorithm(SQLCIPHER_HMAC_SHA512);
      }
    } else {
      int algorithm = sqlcipher_get_default_hmac_algorithm();
      if(algorithm == SQLCIPHER_HMAC_SHA1) {
        codec_vdbe_return_string(pParse, "cipher_default_hmac_algorithm", SQLCIPHER_HMAC_SHA1_LABEL, P4_TRANSIENT);
      } else if(algorithm == SQLCIPHER_HMAC_SHA256) {
        codec_vdbe_return_string(pParse, "cipher_default_hmac_algorithm", SQLCIPHER_HMAC_SHA256_LABEL, P4_TRANSIENT);
      } else if(algorithm == SQLCIPHER_HMAC_SHA512) {
        codec_vdbe_return_string(pParse, "cipher_default_hmac_algorithm", SQLCIPHER_HMAC_SHA512_LABEL, P4_TRANSIENT);
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_kdf_algorithm")==0 ){
    if(ctx) {
      if(zRight) {
        rc = SQLITE_ERROR;
        if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA256);
        } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL) == 0) {
          rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA512);
        }
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
      } else {
        int algorithm = sqlcipher_codec_ctx_get_kdf_algorithm(ctx);
        if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
          codec_vdbe_return_string(pParse, "cipher_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL, P4_TRANSIENT);
        } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
          codec_vdbe_return_string(pParse, "cipher_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL, P4_TRANSIENT);
        } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
          codec_vdbe_return_string(pParse, "cipher_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL, P4_TRANSIENT);
        }
      }
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_kdf_algorithm")==0 ){
    if(zRight) {
      rc = SQLITE_ERROR;
      if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL) == 0) {
        rc = sqlcipher_set_default_kdf_algorithm(SQLCIPHER_PBKDF2_HMAC_SHA1);
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL) == 0) {
        rc = sqlcipher_set_default_kdf_algorithm(SQLCIPHER_PBKDF2_HMAC_SHA256);
      } else if(sqlite3_stricmp(zRight, SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL) == 0) {
        rc = sqlcipher_set_default_kdf_algorithm(SQLCIPHER_PBKDF2_HMAC_SHA512);
      }
    } else {
      int algorithm = sqlcipher_get_default_kdf_algorithm();
      if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
        codec_vdbe_return_string(pParse, "cipher_default_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL, P4_TRANSIENT);
      } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
        codec_vdbe_return_string(pParse, "cipher_default_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL, P4_TRANSIENT);
      } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
        codec_vdbe_return_string(pParse, "cipher_default_kdf_algorithm", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL, P4_TRANSIENT);
      }
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_compatibility")==0 ){
    if(ctx) {
      if(zRight) {
        int version = atoi(zRight); 

        switch(version) {
          case 1: 
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 4000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 0);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          case 2: 
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 4000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          case 3:
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 1024);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 64000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;

          default:
            rc = sqlcipher_codec_ctx_set_pagesize(ctx, 4096);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_hmac_algorithm(ctx, SQLCIPHER_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_algorithm(ctx, SQLCIPHER_PBKDF2_HMAC_SHA512);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_kdf_iter(ctx, 256000); 
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            rc = sqlcipher_codec_ctx_set_use_hmac(ctx, 1);
            if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
            break;
        }  

        rc = codec_set_btree_to_codec_pagesize(db, pDb, ctx);
        if (rc != SQLITE_OK) sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
      } 
    }
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_default_compatibility")==0 ){
    if(zRight) {
      int version = atoi(zRight); 
      switch(version) {
        case 1: 
          sqlcipher_set_default_pagesize(1024);
          sqlcipher_set_default_hmac_algorithm(SQLCIPHER_HMAC_SHA1);
          sqlcipher_set_default_kdf_algorithm(SQLCIPHER_PBKDF2_HMAC_SHA1);
          sqlcipher_set_default_kdf_iter(4000);
          sqlcipher_set_default_use_hmac(0);
          break;

        case 2: 
          sqlcipher_set_default_pagesize(1024);
          sqlcipher_set_default_hmac_algorithm(SQLCIPHER_HMAC_SHA1);
          sqlcipher_set_default_kdf_algorithm(SQLCIPHER_PBKDF2_HMAC_SHA1);
          sqlcipher_set_default_kdf_iter(4000);
          sqlcipher_set_default_use_hmac(1);
          break;

        case 3:
          sqlcipher_set_default_pagesize(1024);
          sqlcipher_set_default_hmac_algorithm(SQLCIPHER_HMAC_SHA1);
          sqlcipher_set_default_kdf_algorithm(SQLCIPHER_PBKDF2_HMAC_SHA1);
          sqlcipher_set_default_kdf_iter(64000);
          sqlcipher_set_default_use_hmac(1);
          break;

        default:
          sqlcipher_set_default_pagesize(4096);
          sqlcipher_set_default_hmac_algorithm(SQLCIPHER_HMAC_SHA512);
          sqlcipher_set_default_kdf_algorithm(SQLCIPHER_PBKDF2_HMAC_SHA512);
          sqlcipher_set_default_kdf_iter(256000);
          sqlcipher_set_default_use_hmac(1);
          break;
      }  
    } 
  }else 
  if( sqlite3_stricmp(zLeft,"cipher_memory_security")==0 ){
    if( zRight ) {
      sqlcipher_set_mem_security(sqlite3GetBoolean(zRight,1));
    } else {
      char *on = sqlite3_mprintf("%d", sqlcipher_get_mem_security());
      codec_vdbe_return_string(pParse, "cipher_memory_security", on, P4_DYNAMIC);
    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_settings")==0 ){
    if(ctx) {
      int algorithm;
      char *pragma;

      pragma = sqlite3_mprintf("PRAGMA kdf_iter = %d;", sqlcipher_codec_ctx_get_kdf_iter(ctx));
      codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_page_size = %d;", sqlcipher_codec_ctx_get_pagesize(ctx));
      codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_use_hmac = %d;", sqlcipher_codec_ctx_get_use_hmac(ctx));
      codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      pragma = sqlite3_mprintf("PRAGMA cipher_plaintext_header_size = %d;", sqlcipher_codec_ctx_get_plaintext_header_size(ctx));
      codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      algorithm = sqlcipher_codec_ctx_get_hmac_algorithm(ctx);
      pragma = NULL;
      if(algorithm == SQLCIPHER_HMAC_SHA1) {
        pragma = sqlite3_mprintf("PRAGMA cipher_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA1_LABEL);
      } else if(algorithm == SQLCIPHER_HMAC_SHA256) {
        pragma = sqlite3_mprintf("PRAGMA cipher_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA256_LABEL);
      } else if(algorithm == SQLCIPHER_HMAC_SHA512) {
        pragma = sqlite3_mprintf("PRAGMA cipher_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA512_LABEL);
      }
      codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

      algorithm = sqlcipher_codec_ctx_get_kdf_algorithm(ctx);
      pragma = NULL;
      if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
        pragma = sqlite3_mprintf("PRAGMA cipher_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL);
      } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
        pragma = sqlite3_mprintf("PRAGMA cipher_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL);
      } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
        pragma = sqlite3_mprintf("PRAGMA cipher_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL);
      }
      codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    }
  }else
  if( sqlite3_stricmp(zLeft,"cipher_default_settings")==0 ){
    int algorithm;
    char *pragma;

    pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_iter = %d;", sqlcipher_get_default_kdf_iter());
    codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_page_size = %d;", sqlcipher_get_default_pagesize());
    codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_use_hmac = %d;", sqlcipher_get_default_use_hmac());
    codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    pragma = sqlite3_mprintf("PRAGMA cipher_default_plaintext_header_size = %d;", sqlcipher_get_default_plaintext_header_size());
    codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    algorithm = sqlcipher_get_default_hmac_algorithm();
    pragma = NULL;
    if(algorithm == SQLCIPHER_HMAC_SHA1) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA1_LABEL);
    } else if(algorithm == SQLCIPHER_HMAC_SHA256) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA256_LABEL);
    } else if(algorithm == SQLCIPHER_HMAC_SHA512) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_hmac_algorithm = %s;", SQLCIPHER_HMAC_SHA512_LABEL);
    }
    codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);

    algorithm = sqlcipher_get_default_kdf_algorithm();
    pragma = NULL;
    if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA1) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA1_LABEL);
    } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA256) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA256_LABEL);
    } else if(algorithm == SQLCIPHER_PBKDF2_HMAC_SHA512) {
      pragma = sqlite3_mprintf("PRAGMA cipher_default_kdf_algorithm = %s;", SQLCIPHER_PBKDF2_HMAC_SHA512_LABEL);
    }
    codec_vdbe_return_string(pParse, "pragma", pragma, P4_DYNAMIC);
  }else
  if( sqlite3_stricmp(zLeft,"cipher_integrity_check")==0 ){
    if(ctx) {
      sqlcipher_codec_ctx_integrity_check(ctx, pParse, "cipher_integrity_check");
    }
  } else
  if( sqlite3_stricmp(zLeft, "cipher_trace_filter")==0 && zRight){
      unsigned int filter = 0;
      printf("%s\n",zRight);
      if(sqlite3_strlike("%CORE%", zRight, '\'')==0) filter |= SQLCIPHER_TRACE_CORE;
      if(sqlite3_strlike("%MEMORY%", zRight, '\'')==0) filter |= SQLCIPHER_TRACE_MEMORY;
      if(sqlite3_strlike("%MUTEX%", zRight, '\'')==0) filter |= SQLCIPHER_TRACE_MUTEX;
      if(sqlite3_strlike("%PROVIDER%", zRight, '\'')==0) filter |= SQLCIPHER_TRACE_PROVIDER;
      if(sqlite3_strlike("%ALL%", zRight, '\'')==0) filter |= SQLCIPHER_TRACE_ALL;
      sqlcipher_set_trace_filter(filter);
      codec_vdbe_return_string(pParse, "cipher_trace_filter", sqlite3_mprintf("%u", filter), P4_DYNAMIC);
  } else
  if( sqlite3_stricmp(zLeft, "cipher_trace")== 0 && zRight ){
      char *profile_status = sqlite3_mprintf("%d", sqlcipher_set_trace(zRight));
      codec_vdbe_return_string(pParse, "cipher_trace", profile_status, P4_DYNAMIC);
  }else {
    return 0;
  }
  return 1;
}

/* these constants are used internally within SQLite's pager.c to differentiate between
   operations on the main database or journal pages. This is important in the context
   of a rekey operations, where the journal must be written using the original key 
   material (to allow a transactional rollback), while the new database pages are being
   written with the new key material*/
#define CODEC_READ_OP 3
#define CODEC_WRITE_OP 6
#define CODEC_JOURNAL_OP 7

/*
 * sqlite3Codec can be called in multiple modes.
 * encrypt mode - expected to return a pointer to the 
 *   encrypted data without altering pData.
 * decrypt mode - expected to return a pointer to pData, with
 *   the data decrypted in the input buffer
 */
static void* sqlite3Codec(void *iCtx, void *data, Pgno pgno, int mode) {
  codec_ctx *ctx = (codec_ctx *) iCtx;
  int offset = 0, rc = 0;
  int page_sz = sqlcipher_codec_ctx_get_pagesize(ctx); 
  unsigned char *pData = (unsigned char *) data;
  void *buffer = sqlcipher_codec_ctx_get_data(ctx);
  int plaintext_header_sz = sqlcipher_codec_ctx_get_plaintext_header_size(ctx);
  int cctx = CIPHER_READ_CTX;

  CODEC_TRACE("sqlite3Codec: entered pgno=%d, mode=%d, page_sz=%d\n", pgno, mode, page_sz);

#ifdef SQLCIPHER_EXT
  if(sqlcipher_license_check(ctx) != SQLITE_OK) return NULL;
#endif

  /* call to derive keys if not present yet */
  if((rc = sqlcipher_codec_key_derive(ctx)) != SQLITE_OK) {
   CODEC_TRACE("sqlite3Codec: error occurred during key derivation: %d\n", rc);
   sqlcipher_codec_ctx_set_error(ctx, rc); 
   return NULL;
  }

  /* if the plaintext_header_size is negative that means an invalid size was set via 
     PRAGMA. We can't set the error state on the pager at that point because the pager
     may not be open yet. However, this is a fatal error state, so abort the codec */
  if(plaintext_header_sz < 0) {
    CODEC_TRACE("sqlite3Codec: error invalid plaintext_header_sz: %d\n", plaintext_header_sz);
    sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR);
    return NULL;
  }

  if(pgno == 1) /* adjust starting pointers in data page for header offset on first page*/   
    offset = plaintext_header_sz ? plaintext_header_sz : FILE_HEADER_SZ; 
  

  CODEC_TRACE("sqlite3Codec: switch mode=%d offset=%d\n",  mode, offset);
  switch(mode) {
    case CODEC_READ_OP: /* decrypt */
      if(pgno == 1) /* copy initial part of file header or SQLite magic to buffer */ 
        memcpy(buffer, plaintext_header_sz ? pData : (void *) SQLITE_FILE_HEADER, offset); 

      rc = sqlcipher_page_cipher(ctx, cctx, pgno, CIPHER_DECRYPT, page_sz - offset, pData + offset, (unsigned char*)buffer + offset);
#ifdef SQLCIPHER_TEST
      if((sqlcipher_get_test_flags() & TEST_FAIL_DECRYPT) > 0 && sqlcipher_get_test_fail()) {
        rc = SQLITE_ERROR;
        fprintf(stderr, "simulating decryption failure for pgno=%d, mode=%d, page_sz=%d\n", pgno, mode, page_sz);
      }
#endif
      if(rc != SQLITE_OK) {
        /* failure to decrypt a page is considered a permanent error and will render the pager unusable
           in order to prevent inconsistent data being loaded into page cache */
        CODEC_TRACE("sqlite3Codec: error decrypting page data: %d\n", rc);
        sqlcipher_memset((unsigned char*) buffer+offset, 0, page_sz-offset);
        sqlcipher_codec_ctx_set_error(ctx, rc);
      }
      memcpy(pData, buffer, page_sz); /* copy buffer data back to pData and return */
      return pData;
      break;

    case CODEC_WRITE_OP: /* encrypt database page, operate on write context and fall through to case 7, so the write context is used*/
      cctx = CIPHER_WRITE_CTX; 

    case CODEC_JOURNAL_OP: /* encrypt journal page, operate on read context use to get the original page data from the database */ 
      if(pgno == 1) { /* copy initial part of file header or salt to buffer */ 
        void *kdf_salt = NULL; 
        /* retrieve the kdf salt */
        if((rc = sqlcipher_codec_ctx_get_kdf_salt(ctx, &kdf_salt)) != SQLITE_OK) {
          CODEC_TRACE("sqlite3Codec: error retrieving salt: %d\n", rc);
          sqlcipher_codec_ctx_set_error(ctx, rc); 
          return NULL;
        }
        memcpy(buffer, plaintext_header_sz ? pData : kdf_salt, offset); 
      }
      rc = sqlcipher_page_cipher(ctx, cctx, pgno, CIPHER_ENCRYPT, page_sz - offset, pData + offset, (unsigned char*)buffer + offset);
#ifdef SQLCIPHER_TEST
      if((sqlcipher_get_test_flags() & TEST_FAIL_ENCRYPT) > 0 && sqlcipher_get_test_fail()) {
        rc = SQLITE_ERROR;
        fprintf(stderr, "simulating encryption failure for pgno=%d, mode=%d, page_sz=%d\n", pgno, mode, page_sz);
      }
#endif
      if(rc != SQLITE_OK) {
        /* failure to encrypt a page is considered a permanent error and will render the pager unusable
           in order to prevent corrupted pages from being written to the main databased when using WAL */
        CODEC_TRACE("sqlite3Codec: error encrypting page data: %d\n", rc);
        sqlcipher_memset((unsigned char*)buffer+offset, 0, page_sz-offset);
        sqlcipher_codec_ctx_set_error(ctx, rc);
        return NULL;
      }
      return buffer; /* return persistent buffer data, pData remains intact */
      break;

    default:
      CODEC_TRACE("sqlite3Codec: error unsupported codec mode %d\n", mode);
      sqlcipher_codec_ctx_set_error(ctx, SQLITE_ERROR); /* unsupported mode, set error */
      return pData;
      break;
  }
}

static void sqlite3FreeCodecArg(void *pCodecArg) {
  codec_ctx *ctx = (codec_ctx *) pCodecArg;
  if(pCodecArg == NULL) return;
  sqlcipher_codec_ctx_free(&ctx); /* wipe and free allocated memory for the context */
  sqlcipher_deactivate(); /* cleanup related structures, OpenSSL etc, when codec is detatched */
}

int sqlite3CodecAttach(sqlite3* db, int nDb, const void *zKey, int nKey) {
  struct Db *pDb = &db->aDb[nDb];

  CODEC_TRACE("sqlite3CodecAttach: entered db=%p, nDb=%d zKey=%p, nKey=%d\n", db, nDb, zKey, nKey);


  if(nKey && zKey && pDb->pBt) {
    int rc;
    Pager *pPager = pDb->pBt->pBt->pPager;
    sqlite3_file *fd;
    codec_ctx *ctx;

    /* check if the sqlite3_file is open, and if not force handle to NULL */ 
    if((fd = sqlite3PagerFile(pPager))->pMethods == 0) fd = NULL; 

    CODEC_TRACE("sqlite3CodecAttach: calling sqlcipher_activate()\n");
    sqlcipher_activate(); /* perform internal initialization for sqlcipher */

    CODEC_TRACE_MUTEX("sqlite3CodecAttach: entering database mutex %p\n", db->mutex);
    sqlite3_mutex_enter(db->mutex);
    CODEC_TRACE_MUTEX("sqlite3CodecAttach: entered database mutex %p\n", db->mutex);

#ifdef SQLCIPHER_EXT
    if((rc = sqlite3_set_authorizer(db, sqlcipher_license_authorizer, db)) != SQLITE_OK) {
      sqlite3_mutex_leave(db->mutex);
      return rc;
    }
#endif

    /* point the internal codec argument against the contet to be prepared */
    CODEC_TRACE("sqlite3CodecAttach: calling sqlcipher_codec_ctx_init()\n");
    rc = sqlcipher_codec_ctx_init(&ctx, pDb, pDb->pBt->pBt->pPager, zKey, nKey);

    if(rc != SQLITE_OK) {
      /* initialization failed, do not attach potentially corrupted context */
      CODEC_TRACE("sqlite3CodecAttach: context initialization failed with rc=%d\n", rc);
      /* force an error at the pager level, such that even the upstream caller ignores the return code
         the pager will be in an error state and will process no further operations */
      sqlite3pager_error(pPager, rc);
      pDb->pBt->pBt->db->errCode = rc;
      CODEC_TRACE_MUTEX("sqlite3CodecAttach: leaving database mutex %p (early return on rc=%d)\n", db->mutex, rc);
      sqlite3_mutex_leave(db->mutex);
      CODEC_TRACE_MUTEX("sqlite3CodecAttach: left database mutex %p (early return on rc=%d)\n", db->mutex, rc);
      return rc;
    }

    CODEC_TRACE("sqlite3CodecAttach: calling sqlite3PagerSetCodec()\n");
    sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), sqlite3Codec, NULL, sqlite3FreeCodecArg, (void *) ctx);

    CODEC_TRACE("sqlite3CodecAttach: calling codec_set_btree_to_codec_pagesize()\n");
    codec_set_btree_to_codec_pagesize(db, pDb, ctx);

    /* force secure delete. This has the benefit of wiping internal data when deleted
       and also ensures that all pages are written to disk (i.e. not skipped by
       sqlite3PagerDontWrite optimizations) */ 
    CODEC_TRACE("sqlite3CodecAttach: calling sqlite3BtreeSecureDelete()\n");
    sqlite3BtreeSecureDelete(pDb->pBt, 1); 

    /* if fd is null, then this is an in-memory database and
       we dont' want to overwrite the AutoVacuum settings
       if not null, then set to the default */
    if(fd != NULL) { 
      CODEC_TRACE("sqlite3CodecAttach: calling sqlite3BtreeSetAutoVacuum()\n");
      sqlite3BtreeSetAutoVacuum(pDb->pBt, SQLITE_DEFAULT_AUTOVACUUM);
    }
    CODEC_TRACE_MUTEX("sqlite3CodecAttach: leaving database mutex %p\n", db->mutex);
    sqlite3_mutex_leave(db->mutex);
    CODEC_TRACE_MUTEX("sqlite3CodecAttach: left database mutex %p\n", db->mutex);
  }
  return SQLITE_OK;
}

int sqlcipher_find_db_index(sqlite3 *db, const char *zDb) {
  int db_index;
  if(zDb == NULL){
    return 0;
  }
  for(db_index = 0; db_index < db->nDb; db_index++) {
    struct Db *pDb = &db->aDb[db_index];
    if(strcmp(pDb->zDbSName, zDb) == 0) {
      return db_index;
    }
  }
  return 0;
}

void sqlite3_activate_see(const char* in) {
  /* do nothing, security enhancements are always active */
}

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
  CODEC_TRACE("sqlite3_key entered: db=%p pKey=%p nKey=%d\n", db, pKey, nKey);
  return sqlite3_key_v2(db, "main", pKey, nKey);
}

int sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
  CODEC_TRACE("sqlite3_key_v2: entered db=%p zDb=%s pKey=%p nKey=%d\n", db, zDb, pKey, nKey);
  /* attach key if db and pKey are not null and nKey is > 0 */
  if(db && pKey && nKey) {
    int db_index = sqlcipher_find_db_index(db, zDb);
    return sqlite3CodecAttach(db, db_index, pKey, nKey); 
  }
  return SQLITE_ERROR;
}

int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey) {
  CODEC_TRACE("sqlite3_rekey entered: db=%p pKey=%p nKey=%d\n", db, pKey, nKey);
  return sqlite3_rekey_v2(db, "main", pKey, nKey);
}

/* sqlite3_rekey_v2
** Given a database, this will reencrypt the database using a new key.
** There is only one possible modes of operation - to encrypt a database
** that is already encrpyted. If the database is not already encrypted
** this should do nothing
** The proposed logic for this function follows:
** 1. Determine if the database is already encryptped
** 2. If there is NOT already a key present do nothing
** 3. If there is a key present, re-encrypt the database with the new key
*/
int sqlite3_rekey_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
  CODEC_TRACE("sqlite3_rekey_v2: entered db=%p zDb=%s pKey=%p, nKey=%d\n", db, zDb, pKey, nKey);
  if(db && pKey && nKey) {
    int db_index = sqlcipher_find_db_index(db, zDb);
    struct Db *pDb = &db->aDb[db_index];
    CODEC_TRACE("sqlite3_rekey_v2: database pDb=%p db_index:%d\n", pDb, db_index);
    if(pDb->pBt) {
      codec_ctx *ctx;
      int rc, page_count;
      Pgno pgno;
      PgHdr *page;
      Pager *pPager = pDb->pBt->pBt->pPager;

      ctx = (codec_ctx*) sqlite3PagerGetCodec(pDb->pBt->pBt->pPager);
     
      if(ctx == NULL) { 
        /* there was no codec attached to this database, so this should do nothing! */ 
        CODEC_TRACE("sqlite3_rekey_v2: no codec attached to db, exiting\n");
        return SQLITE_OK;
      }

      CODEC_TRACE_MUTEX("sqlite3_rekey_v2: entering database mutex %p\n", db->mutex);
      sqlite3_mutex_enter(db->mutex);
      CODEC_TRACE_MUTEX("sqlite3_rekey_v2: entered database mutex %p\n", db->mutex);

      codec_set_pass_key(db, db_index, pKey, nKey, CIPHER_WRITE_CTX);
    
      /* do stuff here to rewrite the database 
      ** 1. Create a transaction on the database
      ** 2. Iterate through each page, reading it and then writing it.
      ** 3. If that goes ok then commit and put ctx->rekey into ctx->key
      **    note: don't deallocate rekey since it may be used in a subsequent iteration 
      */
      rc = sqlite3BtreeBeginTrans(pDb->pBt, 1, 0); /* begin write transaction */
      sqlite3PagerPagecount(pPager, &page_count);
      for(pgno = 1; rc == SQLITE_OK && pgno <= (unsigned int)page_count; pgno++) { /* pgno's start at 1 see pager.c:pagerAcquire */
        if(!sqlite3pager_is_mj_pgno(pPager, pgno)) { /* skip this page (see pager.c:pagerAcquire for reasoning) */
          rc = sqlite3PagerGet(pPager, pgno, &page, 0);
          if(rc == SQLITE_OK) { /* write page see pager_incr_changecounter for example */
            rc = sqlite3PagerWrite(page);
            if(rc == SQLITE_OK) {
              sqlite3PagerUnref(page);
            } else {
             CODEC_TRACE("sqlite3_rekey_v2: error %d occurred writing page %d\n", rc, pgno);  
            }
          } else {
             CODEC_TRACE("sqlite3_rekey_v2: error %d occurred getting page %d\n", rc, pgno);  
          }
        } 
      }

      /* if commit was successful commit and copy the rekey data to current key, else rollback to release locks */
      if(rc == SQLITE_OK) { 
        CODEC_TRACE("sqlite3_rekey_v2: committing\n");
        rc = sqlite3BtreeCommit(pDb->pBt); 
        sqlcipher_codec_key_copy(ctx, CIPHER_WRITE_CTX);
      } else {
        CODEC_TRACE("sqlite3_rekey_v2: rollback\n");
        sqlite3BtreeRollback(pDb->pBt, SQLITE_ABORT_ROLLBACK, 0);
      }

      CODEC_TRACE_MUTEX("sqlite3_rekey_v2: leaving database mutex %p\n", db->mutex);
      sqlite3_mutex_leave(db->mutex);
      CODEC_TRACE_MUTEX("sqlite3_rekey_v2: left database mutex %p\n", db->mutex);
    }
    return SQLITE_OK;
  }
  return SQLITE_ERROR;
}

void sqlite3CodecGetKey(sqlite3* db, int nDb, void **zKey, int *nKey) {
  struct Db *pDb = &db->aDb[nDb];
  CODEC_TRACE("sqlite3CodecGetKey: entered db=%p, nDb=%d\n", db, nDb);
  if( pDb->pBt ) {
    codec_ctx *ctx = (codec_ctx*) sqlite3PagerGetCodec(pDb->pBt->pBt->pPager);
    
    if(ctx) {
      /* pass back the keyspec from the codec, unless PRAGMA cipher_store_pass
         is set or keyspec has not yet been derived, in which case pass
         back the password key material */
      sqlcipher_codec_get_keyspec(ctx, zKey, nKey);
      if(sqlcipher_codec_get_store_pass(ctx) == 1 || *zKey == NULL) {
        sqlcipher_codec_get_pass(ctx, zKey, nKey);
      }
    } else {
      *zKey = NULL;
      *nKey = 0;
    }
  }
}

/*
 * Implementation of an "export" function that allows a caller
 * to duplicate the main database to an attached database. This is intended
 * as a conveneince for users who need to:
 * 
 *   1. migrate from an non-encrypted database to an encrypted database
 *   2. move from an encrypted database to a non-encrypted database
 *   3. convert beween the various flavors of encrypted databases.  
 *
 * This implementation is based heavily on the procedure and code used
 * in vacuum.c, but is exposed as a function that allows export to any
 * named attached database.
 */

/*
** Finalize a prepared statement.  If there was an error, store the
** text of the error message in *pzErrMsg.  Return the result code.
** 
** Based on vacuumFinalize from vacuum.c
*/
static int sqlcipher_finalize(sqlite3 *db, sqlite3_stmt *pStmt, char **pzErrMsg){
  int rc;
  rc = sqlite3VdbeFinalize((Vdbe*)pStmt);
  if( rc ){
    sqlite3SetString(pzErrMsg, db, sqlite3_errmsg(db));
  }
  return rc;
}

/*
** Execute zSql on database db. Return an error code.
** 
** Based on execSql from vacuum.c
*/
static int sqlcipher_execSql(sqlite3 *db, char **pzErrMsg, const char *zSql){
  sqlite3_stmt *pStmt;
  VVA_ONLY( int rc; )
  if( !zSql ){
    return SQLITE_NOMEM;
  }
  if( SQLITE_OK!=sqlite3_prepare(db, zSql, -1, &pStmt, 0) ){
    sqlite3SetString(pzErrMsg, db, sqlite3_errmsg(db));
    return sqlite3_errcode(db);
  }
  VVA_ONLY( rc = ) sqlite3_step(pStmt);
  assert( rc!=SQLITE_ROW );
  return sqlcipher_finalize(db, pStmt, pzErrMsg);
}

/*
** Execute zSql on database db. The statement returns exactly
** one column. Execute this as SQL on the same database.
** 
** Based on execExecSql from vacuum.c
*/
static int sqlcipher_execExecSql(sqlite3 *db, char **pzErrMsg, const char *zSql){
  sqlite3_stmt *pStmt;
  int rc;

  rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
  if( rc!=SQLITE_OK ) return rc;

  while( SQLITE_ROW==sqlite3_step(pStmt) ){
    rc = sqlcipher_execSql(db, pzErrMsg, (char*)sqlite3_column_text(pStmt, 0));
    if( rc!=SQLITE_OK ){
      sqlcipher_finalize(db, pStmt, pzErrMsg);
      return rc;
    }
  }

  return sqlcipher_finalize(db, pStmt, pzErrMsg);
}

/*
 * copy database and schema from the main database to an attached database
 * 
 * Based on sqlite3RunVacuum from vacuum.c
*/
void sqlcipher_exportFunc(sqlite3_context *context, int argc, sqlite3_value **argv) {
  sqlite3 *db = sqlite3_context_db_handle(context);
  const char* targetDb, *sourceDb; 
  int targetDb_idx = 0;
  u64 saved_flags = db->flags;        /* Saved value of the db->flags */
  u32 saved_mDbFlags = db->mDbFlags;        /* Saved value of the db->mDbFlags */
  int saved_nChange = db->nChange;      /* Saved value of db->nChange */
  int saved_nTotalChange = db->nTotalChange; /* Saved value of db->nTotalChange */
  u8 saved_mTrace = db->mTrace;        /* Saved value of db->mTrace */
  int rc = SQLITE_OK;     /* Return code from service routines */
  char *zSql = NULL;         /* SQL statements */
  char *pzErrMsg = NULL;

  if(argc != 1 && argc != 2) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("invalid number of arguments (%d) passed to sqlcipher_export", argc);
    goto end_of_export;
  }

  if(sqlite3_value_type(argv[0]) == SQLITE_NULL) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("target database can't be NULL");
    goto end_of_export;
  }

  targetDb = (const char*) sqlite3_value_text(argv[0]); 
  sourceDb = "main";

  if(argc == 2) {
    if(sqlite3_value_type(argv[1]) == SQLITE_NULL) {
      rc = SQLITE_ERROR;
      pzErrMsg = sqlite3_mprintf("target database can't be NULL");
      goto end_of_export;
    }
    sourceDb = (char *) sqlite3_value_text(argv[1]);
  }


  /* if the name of the target is not main, but the index returned is zero 
     there is a mismatch and we should not proceed */
  targetDb_idx =  sqlcipher_find_db_index(db, targetDb);
  if(targetDb_idx == 0 && targetDb != NULL && sqlite3_stricmp("main", targetDb) != 0) {
    rc = SQLITE_ERROR;
    pzErrMsg = sqlite3_mprintf("unknown database %s", targetDb);
    goto end_of_export;
  }
  db->init.iDb = targetDb_idx;

  db->flags |= SQLITE_WriteSchema | SQLITE_IgnoreChecks; 
  db->mDbFlags |= DBFLAG_PreferBuiltin | DBFLAG_Vacuum;
  db->flags &= ~(u64)(SQLITE_ForeignKeys | SQLITE_ReverseOrder | SQLITE_Defensive | SQLITE_CountRows); 
  db->mTrace = 0;

  /* Query the schema of the main database. Create a mirror schema
  ** in the temporary database.
  */
  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM %s.sqlite_schema WHERE type='table' AND name!='sqlite_sequence'"
    "   AND rootpage>0"
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM %s.sqlite_schema WHERE sql LIKE 'CREATE INDEX %%' "
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = sqlite3_mprintf(
    "SELECT sql "
    "  FROM %s.sqlite_schema WHERE sql LIKE 'CREATE UNIQUE INDEX %%'"
  , sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Loop through the tables in the main database. For each, do
  ** an "INSERT INTO rekey_db.xxx SELECT * FROM main.xxx;" to copy
  ** the contents to the temporary database.
  */
  zSql = sqlite3_mprintf(
    "SELECT 'INSERT INTO %s.' || quote(name) "
    "|| ' SELECT * FROM %s.' || quote(name) || ';'"
    "FROM %s.sqlite_schema "
    "WHERE type = 'table' AND name!='sqlite_sequence' "
    "  AND rootpage>0"
  , targetDb, sourceDb, sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Copy over the contents of the sequence table
  */
  zSql = sqlite3_mprintf(
    "SELECT 'INSERT INTO %s.' || quote(name) "
    "|| ' SELECT * FROM %s.' || quote(name) || ';' "
    "FROM %s.sqlite_schema WHERE name=='sqlite_sequence';"
  , targetDb, sourceDb, targetDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execExecSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  /* Copy the triggers, views, and virtual tables from the main database
  ** over to the temporary database.  None of these objects has any
  ** associated storage, so all we have to do is copy their entries
  ** from the SQLITE_MASTER table.
  */
  zSql = sqlite3_mprintf(
    "INSERT INTO %s.sqlite_schema "
    "  SELECT type, name, tbl_name, rootpage, sql"
    "    FROM %s.sqlite_schema"
    "   WHERE type='view' OR type='trigger'"
    "      OR (type='table' AND rootpage=0)"
  , targetDb, sourceDb);
  rc = (zSql == NULL) ? SQLITE_NOMEM : sqlcipher_execSql(db, &pzErrMsg, zSql); 
  if( rc!=SQLITE_OK ) goto end_of_export;
  sqlite3_free(zSql);

  zSql = NULL;
end_of_export:
  db->init.iDb = 0;
  db->flags = saved_flags;
  db->mDbFlags = saved_mDbFlags;
  db->nChange = saved_nChange;
  db->nTotalChange = saved_nTotalChange;
  db->mTrace = saved_mTrace;

  if(zSql) sqlite3_free(zSql);

  if(rc) {
    if(pzErrMsg != NULL) {
      sqlite3_result_error(context, pzErrMsg, -1);
      sqlite3DbFree(db, pzErrMsg);
    } else {
      sqlite3_result_error(context, sqlite3ErrStr(rc), -1);
    }
  }
}
#endif
/* END SQLCIPHER */
