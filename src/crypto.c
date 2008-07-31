/* 
** SQLite Cipher
** crypto.c developed by Stephen Lombardo (Zetetic LLC) 
** sjlombardo at zetetic dot net
** http://zetetic.net
** 
** July 30, 2008
**
** This code is released under the same public domain terms as SQLite itself.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**  
*/
/* BEGIN CRYPTO */
#if defined(SQLITE_HAS_CODEC)

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "sqliteInt.h"
#include "btreeInt.h"
#include "crypto.h"

typedef struct {
  int key_sz;
  Btree *pBt;
  void *key;
  void *rand;
  void *buffer;
} codec_ctx;

static int codec_page_hash(Pgno pgno, const void *in, int inLen, void *out, int *outLen) {
  EVP_MD_CTX mdctx;
  unsigned int md_sz;
  unsigned char md_value[EVP_MAX_MD_SIZE];

  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, DIGEST, NULL);
    
  EVP_DigestUpdate(&mdctx, in, inLen); /* add random "salt" data to hash*/
  EVP_DigestUpdate(&mdctx, &pgno, sizeof(pgno));
  
  EVP_DigestFinal_ex(&mdctx, md_value, &md_sz);
  
  memcpy(out, md_value, md_sz);
    
  EVP_MD_CTX_cleanup(&mdctx);
  memset(md_value, 0, md_sz);
  *outLen =  md_sz;
}

static int codec_passphrase_hash(const void *in, int inLen, void *out, int *outLen) {
  EVP_MD_CTX mdctx;
  unsigned int md_sz;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  
  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, DIGEST, NULL);
  EVP_DigestUpdate(&mdctx, in, inLen);
  EVP_DigestFinal_ex(&mdctx, md_value, &md_sz);
  memcpy(out, md_value, md_sz);
  EVP_MD_CTX_cleanup(&mdctx);
  memset(md_value, 0, md_sz);
  *outLen = md_sz;
}

static int codec_prepare_key(sqlite3 *db, const void *zKey, int nKey, void *out, int *nOut) {
  /* if key string starts with x' then assume this is a blob literal key*/
  if (sqlite3StrNICmp(zKey ,"x'", 2) == 0) { 
    int n = nKey - 3; /* adjust for leading x' and tailing ' */
    int half_n = n/2;
    const char *z = zKey + 2; /* adjust lead offset of x' */ 
    void *key = sqlite3HexToBlob(db, z, n);
    memcpy(out, key, half_n);
    *nOut = half_n;
    
    memset(key, 0, half_n); /* cleanup temporary key data */
    sqlite3_free(key);
  /* otherwise the key is provided as a string so hash it to get key data */
  } else {
    codec_passphrase_hash(zKey, nKey, out, nOut);
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
  unsigned char iv[EVP_MAX_MD_SIZE];
  int iv_sz, tmp_csz, csz;
  
  /* the initilization vector is created from the hash of the
     16 byte database random salt and the page number. This will
     ensure that each page in the database has a unique initialization
     vector */
  codec_page_hash(pgno, ctx->rand, 16, iv, &iv_sz);
  
  EVP_CipherInit(&ectx, CIPHER, NULL, NULL, mode);
  EVP_CIPHER_CTX_set_padding(&ectx, 0);
  EVP_CipherInit(&ectx, NULL, ctx->key, iv, mode);
  EVP_CipherUpdate(&ectx, out, &tmp_csz, in, size);
  csz = tmp_csz;  
  out += tmp_csz;
  EVP_CipherFinal(&ectx, out, &tmp_csz);
  csz += tmp_csz;
  EVP_CIPHER_CTX_cleanup(&ectx);
  assert(size == csz);
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
      emode = 0;
      break;
    case 6: /* encrypt */
    case 7:
      emode = 1;
      break;
    default:
      return pData;
      break;
  }

  if(pgno == 1 ) { 
    /* duplicate first 24 bytes of page 1 exactly to include random header data and page size */
    memcpy(ctx->buffer, pData, HDR_SZ); 

    /* if this is a read & decrypt operation on the first page then copy the 
       first 16 bytes off the page into the context's random salt buffer
       */
    if(emode) {
      memcpy(ctx->buffer, ctx->rand, 16);
    } else {
      memcpy(ctx->rand, pData, 16);
      memcpy(ctx->buffer, SQLITE_FILE_HEADER, 16);
    }
    
    /* adjust starting pointers in data page for header offset */
    codec_cipher(ctx, pgno, emode, pg_sz - HDR_SZ, &pData[HDR_SZ], &ctx->buffer[HDR_SZ]);
  } else {
    codec_cipher(ctx, pgno, emode, pg_sz, pData, ctx->buffer);
  }
  
  if(emode) {
    return ctx->buffer; /* return persistent buffer data, pData remains intact */
  } else {
    memcpy(pData, ctx->buffer, pg_sz); /* copy buffer data back to pData and return */
    return pData;
  }
}

int sqlite3CodecAttach(sqlite3* db, int nDb, const void *zKey, int nKey) {
  void *keyd;
  int len;
  char hout[1024];
  struct Db *pDb = &db->aDb[nDb];
  
  if(nKey && zKey && pDb->pBt) {
    codec_ctx *ctx;
    int rc;
    MemPage *pPage1;

    ctx = sqlite3DbMallocRaw(db, sizeof(codec_ctx));
    if(ctx == NULL) return SQLITE_NOMEM;
    
    ctx->pBt = pDb->pBt; /* assign pointer to database btree structure */
    
    /* assign random salt data. This will be written to the first page
       if this is a new database file. If an existing database file is
       attached this will just be overwritten when the first page is
       read from disk */
    ctx->rand = sqlite3DbMallocRaw(db, 16);
    if(ctx->rand == NULL) return SQLITE_NOMEM;
    
    RAND_pseudo_bytes(ctx->rand, 16);
    
    /* pre-allocate a page buffer of PageSize bytes. This will
       be used as a persistent buffer for encryption and decryption 
       operations to avoid overhead of multiple memory allocations*/
    ctx->buffer = sqlite3DbMallocRaw(db, sqlite3BtreeGetPageSize(ctx->pBt));
    if(ctx->buffer == NULL) return SQLITE_NOMEM;
    
    ctx->key_sz = EVP_CIPHER_key_length(CIPHER);
         
    /* key size should be exactly the same size as nKey since this is
       raw key data at this point */
    assert(nKey == ctx->key_sz);
    
    ctx->key = sqlite3DbMallocRaw(db, ctx->key_sz);
    if(ctx->key == NULL) return SQLITE_NOMEM;
    memcpy(ctx->key, zKey, nKey);
    
    sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), sqlite3Codec, (void *) ctx);
  }
}

int sqlite3FreeCodecArg(void *pCodecArg) {
  codec_ctx *ctx = (codec_ctx *) pCodecArg;
  if(pCodecArg == NULL) return;
  
  if(ctx->key) {
    memset(ctx->key, 0, ctx->key_sz);
    sqlite3_free(ctx->key);
  }
  
  if(ctx->rand) {
    memset(ctx->rand, 0, 16);
    sqlite3_free(ctx->rand);
  }
  
  if(ctx->buffer) {
    memset(ctx->buffer, 0, sqlite3BtreeGetPageSize(ctx->pBt));
    sqlite3_free(ctx->buffer);
  }
  
  memset(ctx, 0, sizeof(codec_ctx));
  sqlite3_free(ctx);
}

void sqlite3_activate_see(const char* in) {
  /* do nothing, security enhancements are always active */
}

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
  if(db) {
    int i, prepared_key_sz;
    int key_sz =  EVP_CIPHER_key_length(CIPHER);
    void *key = sqlite3DbMallocRaw(db, key_sz);
    
    codec_prepare_key(db, pKey, nKey, key, &prepared_key_sz);
    assert(prepared_key_sz == key_sz);
    
    for(i=0; i<db->nDb; i++){
      sqlite3CodecAttach(db, i, key, prepared_key_sz);
    }
    
    memset(key, 0, key_sz); /* cleanup temporary key data */
    sqlite3_free(key);
  }
}

/* FIXME - this should change the password for the database! */
int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey) {
  printf("sorry sqlite3_rekey is not implemented yet\n");
  sqlite3_key(db, pKey, nKey);
}

void sqlite3CodecGetKey(sqlite3* db, int nDb, void **zKey, int *nKey) {
  extern int sqlite3pager_get_codec(Pager *pPager, void * ctx);
  codec_ctx *ctx;
  struct Db *pDb = &db->aDb[nDb];
  
  if( pDb->pBt ) {
    sqlite3pager_get_codec(pDb->pBt->pBt->pPager, (void **) &ctx);
    if(ctx) {
      *zKey = ctx->key;
      *nKey = ctx->key_sz;
    } else {
      *zKey = 0;
      *nKey = 0;  
    }
  }
  
}


#endif
/* END CRYPTO */
