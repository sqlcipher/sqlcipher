/*
** 2005 May 25
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This file contains the implementation of the sqlite3_prepare()
** interface, and routines that contribute to loading the database schema
** from disk.
*/
#include "sqliteInt.h"

/*
** Fill the InitData structure with an error message that indicates
** that the database is corrupt.
*/
static void corruptSchema(
  InitData *pData,     /* Initialization context */
  const char *zObj,    /* Object being parsed at the point of error */
  const char *zExtra   /* Error information */
){
  sqlite3 *db = pData->db;
  if( !db->mallocFailed && (db->flags & SQLITE_WriteSchema)==0 ){
    char *z;
    if( zObj==0 ) zObj = "?";
    z = sqlite3MPrintf(db, "malformed database schema (%s)", zObj);
    if( zExtra ) z = sqlite3MPrintf(db, "%z - %s", z, zExtra);
    sqlite3DbFree(db, *pData->pzErrMsg);
    *pData->pzErrMsg = z;
  }
  pData->rc = db->mallocFailed ? SQLITE_NOMEM_BKPT : SQLITE_CORRUPT_BKPT;
}

/*
** This is the callback routine for the code that initializes the
** database.  See sqlite3Init() below for additional information.
** This routine is also called from the OP_ParseSchema opcode of the VDBE.
**
** Each callback contains the following information:
**
**     argv[0] = name of thing being created
**     argv[1] = root page number for table or index. 0 for trigger or view.
**     argv[2] = SQL text for the CREATE statement.
**
*/
int sqlite3InitCallback(void *pInit, int argc, char **argv, char **NotUsed){
  InitData *pData = (InitData*)pInit;
  sqlite3 *db = pData->db;
  int iDb = pData->iDb;

  assert( argc==3 );
  UNUSED_PARAMETER2(NotUsed, argc);
  assert( sqlite3_mutex_held(db->mutex) );
  DbClearProperty(db, iDb, DB_Empty);
  if( db->mallocFailed ){
    corruptSchema(pData, argv[0], 0);
    return 1;
  }

  assert( iDb>=0 && iDb<db->nDb );
  if( argv==0 ) return 0;   /* Might happen if EMPTY_RESULT_CALLBACKS are on */
  if( argv[1]==0 ){
    corruptSchema(pData, argv[0], 0);
  }else if( sqlite3_strnicmp(argv[2],"create ",7)==0 ){
    /* Call the parser to process a CREATE TABLE, INDEX or VIEW.
    ** But because db->init.busy is set to 1, no VDBE code is generated
    ** or executed.  All the parser does is build the internal data
    ** structures that describe the table, index, or view.
    */
    int rc;
    u8 saved_iDb = db->init.iDb;
    sqlite3_stmt *pStmt;
    TESTONLY(int rcp);            /* Return code from sqlite3_prepare() */

    assert( db->init.busy );
    db->init.iDb = iDb;
    db->init.newTnum = sqlite3Atoi(argv[1]);
    db->init.orphanTrigger = 0;
    TESTONLY(rcp = ) sqlite3_prepare(db, argv[2], -1, &pStmt, 0);
    rc = db->errCode;
    assert( (rc&0xFF)==(rcp&0xFF) );
    db->init.iDb = saved_iDb;
    assert( saved_iDb==0 || (db->flags & SQLITE_Vacuum)!=0 );
    if( SQLITE_OK!=rc ){
      if( db->init.orphanTrigger ){
        assert( iDb==1 );
      }else{
        pData->rc = rc;
        if( rc==SQLITE_NOMEM ){
          sqlite3OomFault(db);
        }else if( rc!=SQLITE_INTERRUPT && (rc&0xFF)!=SQLITE_LOCKED ){
          corruptSchema(pData, argv[0], sqlite3_errmsg(db));
        }
      }
    }
    sqlite3_finalize(pStmt);
  }else if( argv[0]==0 || (argv[2]!=0 && argv[2][0]!=0) ){
    corruptSchema(pData, argv[0], 0);
  }else{
    /* If the SQL column is blank it means this is an index that
    ** was created to be the PRIMARY KEY or to fulfill a UNIQUE
    ** constraint for a CREATE TABLE.  The index should have already
    ** been created when we processed the CREATE TABLE.  All we have
    ** to do here is record the root page number for that index.
    */
    Index *pIndex;
    pIndex = sqlite3FindIndex(db, argv[0], db->aDb[iDb].zDbSName);
    if( pIndex==0 ){
      /* This can occur if there exists an index on a TEMP table which
      ** has the same name as another index on a permanent index.  Since
      ** the permanent table is hidden by the TEMP table, we can also
      ** safely ignore the index on the permanent table.
      */
      /* Do Nothing */;
    }else if( sqlite3GetInt32(argv[1], &pIndex->tnum)==0 ){
      corruptSchema(pData, argv[0], "invalid rootpage");
    }
  }
  return 0;
}

/*
** Attempt to read the database schema and initialize internal
** data structures for a single database file.  The index of the
** database file is given by iDb.  iDb==0 is used for the main
** database.  iDb==1 should never be used.  iDb>=2 is used for
** auxiliary databases.  Return one of the SQLITE_ error codes to
** indicate success or failure.
*/
static int sqlite3InitOne(sqlite3 *db, int iDb, char **pzErrMsg){
  int rc;
  int i;
#ifndef SQLITE_OMIT_DEPRECATED
  int size;
#endif
  Db *pDb;
  char const *azArg[4];
  int meta[5];
  InitData initData;
  const char *zMasterName;
  int openedTransaction = 0;

  assert( iDb>=0 && iDb<db->nDb );
  assert( db->aDb[iDb].pSchema );
  assert( sqlite3_mutex_held(db->mutex) );
  assert( iDb==1 || sqlite3BtreeHoldsMutex(db->aDb[iDb].pBt) );

  /* Construct the in-memory representation schema tables (sqlite_master or
  ** sqlite_temp_master) by invoking the parser directly.  The appropriate
  ** table name will be inserted automatically by the parser so we can just
  ** use the abbreviation "x" here.  The parser will also automatically tag
  ** the schema table as read-only. */
  azArg[0] = zMasterName = SCHEMA_TABLE(iDb);
  azArg[1] = "1";
  azArg[2] = "CREATE TABLE x(type text,name text,tbl_name text,"
                            "rootpage integer,sql text)";
  azArg[3] = 0;
  initData.db = db;
  initData.iDb = iDb;
  initData.rc = SQLITE_OK;
  initData.pzErrMsg = pzErrMsg;
  sqlite3InitCallback(&initData, 3, (char **)azArg, 0);
  if( initData.rc ){
    rc = initData.rc;
    goto error_out;
  }

  /* Create a cursor to hold the database open
  */
  pDb = &db->aDb[iDb];
  if( pDb->pBt==0 ){
    if( !OMIT_TEMPDB && ALWAYS(iDb==1) ){
      DbSetProperty(db, 1, DB_SchemaLoaded);
    }
    return SQLITE_OK;
  }

  /* If there is not already a read-only (or read-write) transaction opened
  ** on the b-tree database, open one now. If a transaction is opened, it 
  ** will be closed before this function returns.  */
  sqlite3BtreeEnter(pDb->pBt);
  if( !sqlite3BtreeIsInReadTrans(pDb->pBt) ){
    rc = sqlite3BtreeBeginTrans(pDb->pBt, 0);
    if( rc!=SQLITE_OK ){
      sqlite3SetString(pzErrMsg, db, sqlite3ErrStr(rc));
      goto initone_error_out;
    }
    openedTransaction = 1;
  }

  /* Get the database meta information.
  **
  ** Meta values are as follows:
  **    meta[0]   Schema cookie.  Changes with each schema change.
  **    meta[1]   File format of schema layer.
  **    meta[2]   Size of the page cache.
  **    meta[3]   Largest rootpage (auto/incr_vacuum mode)
  **    meta[4]   Db text encoding. 1:UTF-8 2:UTF-16LE 3:UTF-16BE
  **    meta[5]   User version
  **    meta[6]   Incremental vacuum mode
  **    meta[7]   unused
  **    meta[8]   unused
  **    meta[9]   unused
  **
  ** Note: The #defined SQLITE_UTF* symbols in sqliteInt.h correspond to
  ** the possible values of meta[4].
  */
  for(i=0; i<ArraySize(meta); i++){
    sqlite3BtreeGetMeta(pDb->pBt, i+1, (u32 *)&meta[i]);
  }
  pDb->pSchema->schema_cookie = meta[BTREE_SCHEMA_VERSION-1];

  /* If opening a non-empty database, check the text encoding. For the
  ** main database, set sqlite3.enc to the encoding of the main database.
  ** For an attached db, it is an error if the encoding is not the same
  ** as sqlite3.enc.
  */
  if( meta[BTREE_TEXT_ENCODING-1] ){  /* text encoding */
    if( iDb==0 ){
#ifndef SQLITE_OMIT_UTF16
      u8 encoding;
      /* If opening the main database, set ENC(db). */
      encoding = (u8)meta[BTREE_TEXT_ENCODING-1] & 3;
      if( encoding==0 ) encoding = SQLITE_UTF8;
      ENC(db) = encoding;
#else
      ENC(db) = SQLITE_UTF8;
#endif
    }else{
      /* If opening an attached database, the encoding much match ENC(db) */
      if( meta[BTREE_TEXT_ENCODING-1]!=ENC(db) ){
        sqlite3SetString(pzErrMsg, db, "attached databases must use the same"
            " text encoding as main database");
        rc = SQLITE_ERROR;
        goto initone_error_out;
      }
    }
  }else{
    DbSetProperty(db, iDb, DB_Empty);
  }
  pDb->pSchema->enc = ENC(db);

  if( pDb->pSchema->cache_size==0 ){
#ifndef SQLITE_OMIT_DEPRECATED
    size = sqlite3AbsInt32(meta[BTREE_DEFAULT_CACHE_SIZE-1]);
    if( size==0 ){ size = SQLITE_DEFAULT_CACHE_SIZE; }
    pDb->pSchema->cache_size = size;
#else
    pDb->pSchema->cache_size = SQLITE_DEFAULT_CACHE_SIZE;
#endif
    sqlite3BtreeSetCacheSize(pDb->pBt, pDb->pSchema->cache_size);
  }

  /*
  ** file_format==1    Version 3.0.0.
  ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
  ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
  ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
  */
  pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
  if( pDb->pSchema->file_format==0 ){
    pDb->pSchema->file_format = 1;
  }
  if( pDb->pSchema->file_format>SQLITE_MAX_FILE_FORMAT ){
    sqlite3SetString(pzErrMsg, db, "unsupported file format");
    rc = SQLITE_ERROR;
    goto initone_error_out;
  }

  /* Ticket #2804:  When we open a database in the newer file format,
  ** clear the legacy_file_format pragma flag so that a VACUUM will
  ** not downgrade the database and thus invalidate any descending
  ** indices that the user might have created.
  */
  if( iDb==0 && meta[BTREE_FILE_FORMAT-1]>=4 ){
    db->flags &= ~SQLITE_LegacyFileFmt;
  }

  /* Read the schema information out of the schema tables
  */
  assert( db->init.busy );
  {
    char *zSql;
    zSql = sqlite3MPrintf(db, 
        "SELECT name, rootpage, sql FROM \"%w\".%s ORDER BY rowid",
        db->aDb[iDb].zDbSName, zMasterName);
#ifndef SQLITE_OMIT_AUTHORIZATION
    {
      sqlite3_xauth xAuth;
      xAuth = db->xAuth;
      db->xAuth = 0;
#endif
      rc = sqlite3_exec(db, zSql, sqlite3InitCallback, &initData, 0);
#ifndef SQLITE_OMIT_AUTHORIZATION
      db->xAuth = xAuth;
    }
#endif
    if( rc==SQLITE_OK ) rc = initData.rc;
    sqlite3DbFree(db, zSql);
#ifndef SQLITE_OMIT_ANALYZE
    if( rc==SQLITE_OK ){
      sqlite3AnalysisLoad(db, iDb);
    }
#endif
  }
  if( db->mallocFailed ){
    rc = SQLITE_NOMEM_BKPT;
    sqlite3ResetAllSchemasOfConnection(db);
  }
  if( rc==SQLITE_OK || (db->flags&SQLITE_WriteSchema)){
    /* Black magic: If the SQLITE_WriteSchema flag is set, then consider
    ** the schema loaded, even if errors occurred. In this situation the 
    ** current sqlite3_prepare() operation will fail, but the following one
    ** will attempt to compile the supplied statement against whatever subset
    ** of the schema was loaded before the error occurred. The primary
    ** purpose of this is to allow access to the sqlite_master table
    ** even when its contents have been corrupted.
    */
    DbSetProperty(db, iDb, DB_SchemaLoaded);
    rc = SQLITE_OK;
  }

  /* Jump here for an error that occurs after successfully allocating
  ** curMain and calling sqlite3BtreeEnter(). For an error that occurs
  ** before that point, jump to error_out.
  */
initone_error_out:
  if( openedTransaction ){
    sqlite3BtreeCommit(pDb->pBt);
  }
  sqlite3BtreeLeave(pDb->pBt);

error_out:
  if( rc==SQLITE_NOMEM || rc==SQLITE_IOERR_NOMEM ){
    sqlite3OomFault(db);
  }
  return rc;
}

/*
** Initialize all database files - the main database file, the file
** used to store temporary tables, and any additional database files
** created using ATTACH statements.  Return a success code.  If an
** error occurs, write an error message into *pzErrMsg.
**
** After a database is initialized, the DB_SchemaLoaded bit is set
** bit is set in the flags field of the Db structure. If the database
** file was of zero-length, then the DB_Empty flag is also set.
*/
int sqlite3Init(sqlite3 *db, char **pzErrMsg){
  int i, rc;
  int commit_internal = !(db->flags&SQLITE_InternChanges);
  
  assert( sqlite3_mutex_held(db->mutex) );
  assert( sqlite3BtreeHoldsMutex(db->aDb[0].pBt) );
  assert( db->init.busy==0 );
  rc = SQLITE_OK;
  db->init.busy = 1;
  ENC(db) = SCHEMA_ENC(db);
  for(i=0; rc==SQLITE_OK && i<db->nDb; i++){
    if( DbHasProperty(db, i, DB_SchemaLoaded) || i==1 ) continue;
    rc = sqlite3InitOne(db, i, pzErrMsg);
    if( rc ){
      sqlite3ResetOneSchema(db, i);
    }
  }

  /* Once all the other databases have been initialized, load the schema
  ** for the TEMP database. This is loaded last, as the TEMP database
  ** schema may contain references to objects in other databases.
  */
#ifndef SQLITE_OMIT_TEMPDB
  assert( db->nDb>1 );
  if( rc==SQLITE_OK && !DbHasProperty(db, 1, DB_SchemaLoaded) ){
    rc = sqlite3InitOne(db, 1, pzErrMsg);
    if( rc ){
      sqlite3ResetOneSchema(db, 1);
    }
  }
#endif

  db->init.busy = 0;
  if( rc==SQLITE_OK && commit_internal ){
    sqlite3CommitInternalChanges(db);
  }

  return rc; 
}

/*
** This routine is a no-op if the database schema is already initialized.
** Otherwise, the schema is loaded. An error code is returned.
*/
int sqlite3ReadSchema(Parse *pParse){
  int rc = SQLITE_OK;
  sqlite3 *db = pParse->db;
  assert( sqlite3_mutex_held(db->mutex) );
  if( !db->init.busy ){
    rc = sqlite3Init(db, &pParse->zErrMsg);
  }
  if( rc!=SQLITE_OK ){
    pParse->rc = rc;
    pParse->nErr++;
  }
  return rc;
}


/*
** Check schema cookies in all databases.  If any cookie is out
** of date set pParse->rc to SQLITE_SCHEMA.  If all schema cookies
** make no changes to pParse->rc.
*/
static void schemaIsValid(Parse *pParse){
  sqlite3 *db = pParse->db;
  int iDb;
  int rc;
  int cookie;

  assert( pParse->checkSchema );
  assert( sqlite3_mutex_held(db->mutex) );
  for(iDb=0; iDb<db->nDb; iDb++){
    int openedTransaction = 0;         /* True if a transaction is opened */
    Btree *pBt = db->aDb[iDb].pBt;     /* Btree database to read cookie from */
    if( pBt==0 ) continue;

    /* If there is not already a read-only (or read-write) transaction opened
    ** on the b-tree database, open one now. If a transaction is opened, it 
    ** will be closed immediately after reading the meta-value. */
    if( !sqlite3BtreeIsInReadTrans(pBt) ){
      rc = sqlite3BtreeBeginTrans(pBt, 0);
      if( rc==SQLITE_NOMEM || rc==SQLITE_IOERR_NOMEM ){
        sqlite3OomFault(db);
      }
      if( rc!=SQLITE_OK ) return;
      openedTransaction = 1;
    }

    /* Read the schema cookie from the database. If it does not match the 
    ** value stored as part of the in-memory schema representation,
    ** set Parse.rc to SQLITE_SCHEMA. */
    sqlite3BtreeGetMeta(pBt, BTREE_SCHEMA_VERSION, (u32 *)&cookie);
    assert( sqlite3SchemaMutexHeld(db, iDb, 0) );
    if( cookie!=db->aDb[iDb].pSchema->schema_cookie ){
      sqlite3ResetOneSchema(db, iDb);
      pParse->rc = SQLITE_SCHEMA;
    }

    /* Close the transaction, if one was opened. */
    if( openedTransaction ){
      sqlite3BtreeCommit(pBt);
    }
  }
}

/*
** Convert a schema pointer into the iDb index that indicates
** which database file in db->aDb[] the schema refers to.
**
** If the same database is attached more than once, the first
** attached database is returned.
*/
int sqlite3SchemaToIndex(sqlite3 *db, Schema *pSchema){
  int i = -1000000;

  /* If pSchema is NULL, then return -1000000. This happens when code in 
  ** expr.c is trying to resolve a reference to a transient table (i.e. one
  ** created by a sub-select). In this case the return value of this 
  ** function should never be used.
  **
  ** We return -1000000 instead of the more usual -1 simply because using
  ** -1000000 as the incorrect index into db->aDb[] is much 
  ** more likely to cause a segfault than -1 (of course there are assert()
  ** statements too, but it never hurts to play the odds).
  */
  assert( sqlite3_mutex_held(db->mutex) );
  if( pSchema ){
    for(i=0; ALWAYS(i<db->nDb); i++){
      if( db->aDb[i].pSchema==pSchema ){
        break;
      }
    }
    assert( i>=0 && i<db->nDb );
  }
  return i;
}

/*
** Free all memory allocations in the pParse object
*/
void sqlite3ParserReset(Parse *pParse){
  if( pParse ){
    sqlite3 *db = pParse->db;
    sqlite3DbFree(db, pParse->aLabel);
    sqlite3ExprListDelete(db, pParse->pConstExpr);
    if( db ){
      assert( db->lookaside.bDisable >= pParse->disableLookaside );
      db->lookaside.bDisable -= pParse->disableLookaside;
    }
    pParse->disableLookaside = 0;
  }
}

/*
** Compile the UTF-8 encoded SQL statement zSql into a statement handle.
*/
static int sqlite3Prepare(
  sqlite3 *db,              /* Database handle. */
  const char *zSql,         /* UTF-8 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  u32 prepFlags,            /* Zero or more SQLITE_PREPARE_* flags */
  Vdbe *pReprepare,         /* VM being reprepared */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const char **pzTail       /* OUT: End of parsed string */
){
  char *zErrMsg = 0;        /* Error message */
  int rc = SQLITE_OK;       /* Result code */
  int i;                    /* Loop counter */
  Parse sParse;             /* Parsing context */

  memset(&sParse, 0, PARSE_HDR_SZ);
  memset(PARSE_TAIL(&sParse), 0, PARSE_TAIL_SZ);
  sParse.pReprepare = pReprepare;
  assert( ppStmt && *ppStmt==0 );
  /* assert( !db->mallocFailed ); // not true with SQLITE_USE_ALLOCA */
  assert( sqlite3_mutex_held(db->mutex) );

  /* For a long-term use prepared statement avoid the use of
  ** lookaside memory.
  */
  if( prepFlags & SQLITE_PREPARE_PERSISTENT ){
    sParse.disableLookaside++;
    db->lookaside.bDisable++;
  }

  /* Check to verify that it is possible to get a read lock on all
  ** database schemas.  The inability to get a read lock indicates that
  ** some other database connection is holding a write-lock, which in
  ** turn means that the other connection has made uncommitted changes
  ** to the schema.
  **
  ** Were we to proceed and prepare the statement against the uncommitted
  ** schema changes and if those schema changes are subsequently rolled
  ** back and different changes are made in their place, then when this
  ** prepared statement goes to run the schema cookie would fail to detect
  ** the schema change.  Disaster would follow.
  **
  ** This thread is currently holding mutexes on all Btrees (because
  ** of the sqlite3BtreeEnterAll() in sqlite3LockAndPrepare()) so it
  ** is not possible for another thread to start a new schema change
  ** while this routine is running.  Hence, we do not need to hold 
  ** locks on the schema, we just need to make sure nobody else is 
  ** holding them.
  **
  ** Note that setting READ_UNCOMMITTED overrides most lock detection,
  ** but it does *not* override schema lock detection, so this all still
  ** works even if READ_UNCOMMITTED is set.
  */
  for(i=0; i<db->nDb; i++) {
    Btree *pBt = db->aDb[i].pBt;
    if( pBt ){
      assert( sqlite3BtreeHoldsMutex(pBt) );
      rc = sqlite3BtreeSchemaLocked(pBt);
      if( rc ){
        const char *zDb = db->aDb[i].zDbSName;
        sqlite3ErrorWithMsg(db, rc, "database schema is locked: %s", zDb);
        testcase( db->flags & SQLITE_ReadUncommit );
        goto end_prepare;
      }
    }
  }

  sqlite3VtabUnlockList(db);

  sParse.db = db;
  if( nBytes>=0 && (nBytes==0 || zSql[nBytes-1]!=0) ){
    char *zSqlCopy;
    int mxLen = db->aLimit[SQLITE_LIMIT_SQL_LENGTH];
    testcase( nBytes==mxLen );
    testcase( nBytes==mxLen+1 );
    if( nBytes>mxLen ){
      sqlite3ErrorWithMsg(db, SQLITE_TOOBIG, "statement too long");
      rc = sqlite3ApiExit(db, SQLITE_TOOBIG);
      goto end_prepare;
    }
    zSqlCopy = sqlite3DbStrNDup(db, zSql, nBytes);
    if( zSqlCopy ){
      sqlite3RunParser(&sParse, zSqlCopy, &zErrMsg);
      sParse.zTail = &zSql[sParse.zTail-zSqlCopy];
      sqlite3DbFree(db, zSqlCopy);
    }else{
      sParse.zTail = &zSql[nBytes];
    }
  }else{
    sqlite3RunParser(&sParse, zSql, &zErrMsg);
  }
  assert( 0==sParse.nQueryLoop );

  if( sParse.rc==SQLITE_DONE ) sParse.rc = SQLITE_OK;
  if( sParse.checkSchema ){
    schemaIsValid(&sParse);
  }
  if( db->mallocFailed ){
    sParse.rc = SQLITE_NOMEM_BKPT;
  }
  if( pzTail ){
    *pzTail = sParse.zTail;
  }
  rc = sParse.rc;

#ifndef SQLITE_OMIT_EXPLAIN
  if( rc==SQLITE_OK && sParse.pVdbe && sParse.explain ){
    static const char * const azColName[] = {
       "addr", "opcode", "p1", "p2", "p3", "p4", "p5", "comment",
       "selectid", "order", "from", "detail"
    };
    int iFirst, mx;
    if( sParse.explain==2 ){
      sqlite3VdbeSetNumCols(sParse.pVdbe, 4);
      iFirst = 8;
      mx = 12;
    }else{
      sqlite3VdbeSetNumCols(sParse.pVdbe, 8);
      iFirst = 0;
      mx = 8;
    }
    for(i=iFirst; i<mx; i++){
      sqlite3VdbeSetColName(sParse.pVdbe, i-iFirst, COLNAME_NAME,
                            azColName[i], SQLITE_STATIC);
    }
  }
#endif

  if( db->init.busy==0 ){
    sqlite3VdbeSetSql(sParse.pVdbe, zSql, (int)(sParse.zTail-zSql), prepFlags);
  }
  if( sParse.pVdbe && (rc!=SQLITE_OK || db->mallocFailed) ){
    sqlite3VdbeFinalize(sParse.pVdbe);
    assert(!(*ppStmt));
  }else{
    *ppStmt = (sqlite3_stmt*)sParse.pVdbe;
  }

  if( zErrMsg ){
    sqlite3ErrorWithMsg(db, rc, "%s", zErrMsg);
    sqlite3DbFree(db, zErrMsg);
  }else{
    sqlite3Error(db, rc);
  }

  /* Delete any TriggerPrg structures allocated while parsing this statement. */
  while( sParse.pTriggerPrg ){
    TriggerPrg *pT = sParse.pTriggerPrg;
    sParse.pTriggerPrg = pT->pNext;
    sqlite3DbFree(db, pT);
  }

end_prepare:

  sqlite3ParserReset(&sParse);
  rc = sqlite3ApiExit(db, rc);
  assert( (rc&db->errMask)==rc );
  return rc;
}
static int sqlite3LockAndPrepare(
  sqlite3 *db,              /* Database handle. */
  const char *zSql,         /* UTF-8 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  u32 prepFlags,            /* Zero or more SQLITE_PREPARE_* flags */
  Vdbe *pOld,               /* VM being reprepared */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const char **pzTail       /* OUT: End of parsed string */
){
  int rc;

#ifdef SQLITE_ENABLE_API_ARMOR
  if( ppStmt==0 ) return SQLITE_MISUSE_BKPT;
#endif
  *ppStmt = 0;
  if( !sqlite3SafetyCheckOk(db)||zSql==0 ){
    return SQLITE_MISUSE_BKPT;
  }
  sqlite3_mutex_enter(db->mutex);
  sqlite3BtreeEnterAll(db);
  rc = sqlite3Prepare(db, zSql, nBytes, prepFlags, pOld, ppStmt, pzTail);
  if( rc==SQLITE_SCHEMA ){
    sqlite3_finalize(*ppStmt);
    rc = sqlite3Prepare(db, zSql, nBytes, prepFlags, pOld, ppStmt, pzTail);
  }
  sqlite3BtreeLeaveAll(db);
  sqlite3_mutex_leave(db->mutex);
  assert( rc==SQLITE_OK || *ppStmt==0 );
  return rc;
}

/*
** Rerun the compilation of a statement after a schema change.
**
** If the statement is successfully recompiled, return SQLITE_OK. Otherwise,
** if the statement cannot be recompiled because another connection has
** locked the sqlite3_master table, return SQLITE_LOCKED. If any other error
** occurs, return SQLITE_SCHEMA.
*/
int sqlite3Reprepare(Vdbe *p){
  int rc;
  sqlite3_stmt *pNew;
  const char *zSql;
  sqlite3 *db;
  u8 prepFlags;

  assert( sqlite3_mutex_held(sqlite3VdbeDb(p)->mutex) );
  zSql = sqlite3_sql((sqlite3_stmt *)p);
  assert( zSql!=0 );  /* Reprepare only called for prepare_v2() statements */
  db = sqlite3VdbeDb(p);
  assert( sqlite3_mutex_held(db->mutex) );
  prepFlags = sqlite3VdbePrepareFlags(p);
  rc = sqlite3LockAndPrepare(db, zSql, -1, prepFlags, p, &pNew, 0);
  if( rc ){
    if( rc==SQLITE_NOMEM ){
      sqlite3OomFault(db);
    }
    assert( pNew==0 );
    return rc;
  }else{
    assert( pNew!=0 );
  }
  sqlite3VdbeSwap((Vdbe*)pNew, p);
  sqlite3TransferBindings(pNew, (sqlite3_stmt*)p);
  sqlite3VdbeResetStepResult((Vdbe*)pNew);
  sqlite3VdbeFinalize((Vdbe*)pNew);
  return SQLITE_OK;
}


/*
** Two versions of the official API.  Legacy and new use.  In the legacy
** version, the original SQL text is not saved in the prepared statement
** and so if a schema change occurs, SQLITE_SCHEMA is returned by
** sqlite3_step().  In the new version, the original SQL text is retained
** and the statement is automatically recompiled if an schema change
** occurs.
*/
int sqlite3_prepare(
  sqlite3 *db,              /* Database handle. */
  const char *zSql,         /* UTF-8 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const char **pzTail       /* OUT: End of parsed string */
){
  int rc;
  rc = sqlite3LockAndPrepare(db,zSql,nBytes,0,0,ppStmt,pzTail);
  assert( rc==SQLITE_OK || ppStmt==0 || *ppStmt==0 );  /* VERIFY: F13021 */
  return rc;
}
int sqlite3_prepare_v2(
  sqlite3 *db,              /* Database handle. */
  const char *zSql,         /* UTF-8 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const char **pzTail       /* OUT: End of parsed string */
){
  int rc;
  /* EVIDENCE-OF: R-37923-12173 The sqlite3_prepare_v2() interface works
  ** exactly the same as sqlite3_prepare_v3() with a zero prepFlags
  ** parameter.
  **
  ** Proof in that the 5th parameter to sqlite3LockAndPrepare is 0 */
  rc = sqlite3LockAndPrepare(db,zSql,nBytes,SQLITE_PREPARE_SAVESQL,0,
                             ppStmt,pzTail);
  assert( rc==SQLITE_OK || ppStmt==0 || *ppStmt==0 );
  return rc;
}
int sqlite3_prepare_v3(
  sqlite3 *db,              /* Database handle. */
  const char *zSql,         /* UTF-8 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  unsigned int prepFlags,   /* Zero or more SQLITE_PREPARE_* flags */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const char **pzTail       /* OUT: End of parsed string */
){
  int rc;
  /* EVIDENCE-OF: R-56861-42673 sqlite3_prepare_v3() differs from
  ** sqlite3_prepare_v2() only in having the extra prepFlags parameter,
  ** which is a bit array consisting of zero or more of the
  ** SQLITE_PREPARE_* flags.
  **
  ** Proof by comparison to the implementation of sqlite3_prepare_v2()
  ** directly above. */
  rc = sqlite3LockAndPrepare(db,zSql,nBytes,
                 SQLITE_PREPARE_SAVESQL|(prepFlags&SQLITE_PREPARE_MASK),
                 0,ppStmt,pzTail);
  assert( rc==SQLITE_OK || ppStmt==0 || *ppStmt==0 );
  return rc;
}


#ifndef SQLITE_OMIT_UTF16
/*
** Compile the UTF-16 encoded SQL statement zSql into a statement handle.
*/
static int sqlite3Prepare16(
  sqlite3 *db,              /* Database handle. */ 
  const void *zSql,         /* UTF-16 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  u32 prepFlags,            /* Zero or more SQLITE_PREPARE_* flags */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const void **pzTail       /* OUT: End of parsed string */
){
  /* This function currently works by first transforming the UTF-16
  ** encoded string to UTF-8, then invoking sqlite3_prepare(). The
  ** tricky bit is figuring out the pointer to return in *pzTail.
  */
  char *zSql8;
  const char *zTail8 = 0;
  int rc = SQLITE_OK;

#ifdef SQLITE_ENABLE_API_ARMOR
  if( ppStmt==0 ) return SQLITE_MISUSE_BKPT;
#endif
  *ppStmt = 0;
  if( !sqlite3SafetyCheckOk(db)||zSql==0 ){
    return SQLITE_MISUSE_BKPT;
  }
  if( nBytes>=0 ){
    int sz;
    const char *z = (const char*)zSql;
    for(sz=0; sz<nBytes && (z[sz]!=0 || z[sz+1]!=0); sz += 2){}
    nBytes = sz;
  }
  sqlite3_mutex_enter(db->mutex);
  zSql8 = sqlite3Utf16to8(db, zSql, nBytes, SQLITE_UTF16NATIVE);
  if( zSql8 ){
    rc = sqlite3LockAndPrepare(db, zSql8, -1, prepFlags, 0, ppStmt, &zTail8);
  }

  if( zTail8 && pzTail ){
    /* If sqlite3_prepare returns a tail pointer, we calculate the
    ** equivalent pointer into the UTF-16 string by counting the unicode
    ** characters between zSql8 and zTail8, and then returning a pointer
    ** the same number of characters into the UTF-16 string.
    */
    int chars_parsed = sqlite3Utf8CharLen(zSql8, (int)(zTail8-zSql8));
    *pzTail = (u8 *)zSql + sqlite3Utf16ByteLen(zSql, chars_parsed);
  }
  sqlite3DbFree(db, zSql8); 
  rc = sqlite3ApiExit(db, rc);
  sqlite3_mutex_leave(db->mutex);
  return rc;
}

/*
** Two versions of the official API.  Legacy and new use.  In the legacy
** version, the original SQL text is not saved in the prepared statement
** and so if a schema change occurs, SQLITE_SCHEMA is returned by
** sqlite3_step().  In the new version, the original SQL text is retained
** and the statement is automatically recompiled if an schema change
** occurs.
*/
int sqlite3_prepare16(
  sqlite3 *db,              /* Database handle. */ 
  const void *zSql,         /* UTF-16 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const void **pzTail       /* OUT: End of parsed string */
){
  int rc;
  rc = sqlite3Prepare16(db,zSql,nBytes,0,ppStmt,pzTail);
  assert( rc==SQLITE_OK || ppStmt==0 || *ppStmt==0 );  /* VERIFY: F13021 */
  return rc;
}
int sqlite3_prepare16_v2(
  sqlite3 *db,              /* Database handle. */ 
  const void *zSql,         /* UTF-16 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const void **pzTail       /* OUT: End of parsed string */
){
  int rc;
  rc = sqlite3Prepare16(db,zSql,nBytes,SQLITE_PREPARE_SAVESQL,ppStmt,pzTail);
  assert( rc==SQLITE_OK || ppStmt==0 || *ppStmt==0 );  /* VERIFY: F13021 */
  return rc;
}
int sqlite3_prepare16_v3(
  sqlite3 *db,              /* Database handle. */ 
  const void *zSql,         /* UTF-16 encoded SQL statement. */
  int nBytes,               /* Length of zSql in bytes. */
  unsigned int prepFlags,   /* Zero or more SQLITE_PREPARE_* flags */
  sqlite3_stmt **ppStmt,    /* OUT: A pointer to the prepared statement */
  const void **pzTail       /* OUT: End of parsed string */
){
  int rc;
  rc = sqlite3Prepare16(db,zSql,nBytes,
         SQLITE_PREPARE_SAVESQL|(prepFlags&SQLITE_PREPARE_MASK),
         ppStmt,pzTail);
  assert( rc==SQLITE_OK || ppStmt==0 || *ppStmt==0 );  /* VERIFY: F13021 */
  return rc;
}

#endif /* SQLITE_OMIT_UTF16 */
