/*
** 2015-06-08
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
**
** This file contains C code to implement the TreeView debugging routines.
** These routines print a parse tree to standard output for debugging and
** analysis. 
**
** The interfaces in this file is only available when compiling
** with SQLITE_DEBUG.
*/
#include "sqliteInt.h"
#ifdef SQLITE_DEBUG

/*
** Add a new subitem to the tree.  The moreToFollow flag indicates that this
** is not the last item in the tree.
*/
static TreeView *sqlite3TreeViewPush(TreeView *p, u8 moreToFollow){
  if( p==0 ){
    p = sqlite3_malloc64( sizeof(*p) );
    if( p==0 ) return 0;
    memset(p, 0, sizeof(*p));
  }else{
    p->iLevel++;
  }
  assert( moreToFollow==0 || moreToFollow==1 );
  if( p->iLevel<sizeof(p->bLine) ) p->bLine[p->iLevel] = moreToFollow;
  return p;
}

/*
** Finished with one layer of the tree
*/
static void sqlite3TreeViewPop(TreeView *p){
  if( p==0 ) return;
  p->iLevel--;
  if( p->iLevel<0 ) sqlite3_free(p);
}

/*
** Generate a single line of output for the tree, with a prefix that contains
** all the appropriate tree lines
*/
static void sqlite3TreeViewLine(TreeView *p, const char *zFormat, ...){
  va_list ap;
  int i;
  StrAccum acc;
  char zBuf[500];
  sqlite3StrAccumInit(&acc, 0, zBuf, sizeof(zBuf), 0);
  if( p ){
    for(i=0; i<p->iLevel && i<sizeof(p->bLine)-1; i++){
      sqlite3StrAccumAppend(&acc, p->bLine[i] ? "|   " : "    ", 4);
    }
    sqlite3StrAccumAppend(&acc, p->bLine[i] ? "|-- " : "'-- ", 4);
  }
  va_start(ap, zFormat);
  sqlite3VXPrintf(&acc, zFormat, ap);
  va_end(ap);
  assert( acc.nChar>0 );
  if( zBuf[acc.nChar-1]!='\n' ) sqlite3StrAccumAppend(&acc, "\n", 1);
  sqlite3StrAccumFinish(&acc);
  fprintf(stdout,"%s", zBuf);
  fflush(stdout);
}

/*
** Shorthand for starting a new tree item that consists of a single label
*/
static void sqlite3TreeViewItem(TreeView *p, const char *zLabel,u8 moreFollows){
  p = sqlite3TreeViewPush(p, moreFollows);
  sqlite3TreeViewLine(p, "%s", zLabel);
}

/*
** Generate a human-readable description of a WITH clause.
*/
void sqlite3TreeViewWith(TreeView *pView, const With *pWith, u8 moreToFollow){
  int i;
  if( pWith==0 ) return;
  if( pWith->nCte==0 ) return;
  if( pWith->pOuter ){
    sqlite3TreeViewLine(pView, "WITH (0x%p, pOuter=0x%p)",pWith,pWith->pOuter);
  }else{
    sqlite3TreeViewLine(pView, "WITH (0x%p)", pWith);
  }
  if( pWith->nCte>0 ){
    pView = sqlite3TreeViewPush(pView, 1);
    for(i=0; i<pWith->nCte; i++){
      StrAccum x;
      char zLine[1000];
      const struct Cte *pCte = &pWith->a[i];
      sqlite3StrAccumInit(&x, 0, zLine, sizeof(zLine), 0);
      sqlite3XPrintf(&x, "%s", pCte->zName);
      if( pCte->pCols && pCte->pCols->nExpr>0 ){
        char cSep = '(';
        int j;
        for(j=0; j<pCte->pCols->nExpr; j++){
          sqlite3XPrintf(&x, "%c%s", cSep, pCte->pCols->a[j].zName);
          cSep = ',';
        }
        sqlite3XPrintf(&x, ")");
      }
      sqlite3XPrintf(&x, " AS");
      sqlite3StrAccumFinish(&x);
      sqlite3TreeViewItem(pView, zLine, i<pWith->nCte-1);
      sqlite3TreeViewSelect(pView, pCte->pSelect, 0);
      sqlite3TreeViewPop(pView);
    }
    sqlite3TreeViewPop(pView);
  }
}


/*
** Generate a human-readable description of a Select object.
*/
void sqlite3TreeViewSelect(TreeView *pView, const Select *p, u8 moreToFollow){
  int n = 0;
  int cnt = 0;
  if( p==0 ){
    sqlite3TreeViewLine(pView, "nil-SELECT");
    return;
  } 
  pView = sqlite3TreeViewPush(pView, moreToFollow);
  if( p->pWith ){
    sqlite3TreeViewWith(pView, p->pWith, 1);
    cnt = 1;
    sqlite3TreeViewPush(pView, 1);
  }
  do{
    sqlite3TreeViewLine(pView, "SELECT%s%s (0x%p) selFlags=0x%x nSelectRow=%d",
      ((p->selFlags & SF_Distinct) ? " DISTINCT" : ""),
      ((p->selFlags & SF_Aggregate) ? " agg_flag" : ""), p, p->selFlags,
      (int)p->nSelectRow
    );
    if( cnt++ ) sqlite3TreeViewPop(pView);
    if( p->pPrior ){
      n = 1000;
    }else{
      n = 0;
      if( p->pSrc && p->pSrc->nSrc ) n++;
      if( p->pWhere ) n++;
      if( p->pGroupBy ) n++;
      if( p->pHaving ) n++;
      if( p->pOrderBy ) n++;
      if( p->pLimit ) n++;
      if( p->pOffset ) n++;
    }
    sqlite3TreeViewExprList(pView, p->pEList, (n--)>0, "result-set");
    if( p->pSrc && p->pSrc->nSrc ){
      int i;
      pView = sqlite3TreeViewPush(pView, (n--)>0);
      sqlite3TreeViewLine(pView, "FROM");
      for(i=0; i<p->pSrc->nSrc; i++){
        struct SrcList_item *pItem = &p->pSrc->a[i];
        StrAccum x;
        char zLine[100];
        sqlite3StrAccumInit(&x, 0, zLine, sizeof(zLine), 0);
        sqlite3XPrintf(&x, "{%d,*}", pItem->iCursor);
        if( pItem->zDatabase ){
          sqlite3XPrintf(&x, " %s.%s", pItem->zDatabase, pItem->zName);
        }else if( pItem->zName ){
          sqlite3XPrintf(&x, " %s", pItem->zName);
        }
        if( pItem->pTab ){
          sqlite3XPrintf(&x, " tabname=%Q", pItem->pTab->zName);
        }
        if( pItem->zAlias ){
          sqlite3XPrintf(&x, " (AS %s)", pItem->zAlias);
        }
        if( pItem->fg.jointype & JT_LEFT ){
          sqlite3XPrintf(&x, " LEFT-JOIN");
        }
        sqlite3StrAccumFinish(&x);
        sqlite3TreeViewItem(pView, zLine, i<p->pSrc->nSrc-1); 
        if( pItem->pSelect ){
          sqlite3TreeViewSelect(pView, pItem->pSelect, 0);
        }
        if( pItem->fg.isTabFunc ){
          sqlite3TreeViewExprList(pView, pItem->u1.pFuncArg, 0, "func-args:");
        }
        sqlite3TreeViewPop(pView);
      }
      sqlite3TreeViewPop(pView);
    }
    if( p->pWhere ){
      sqlite3TreeViewItem(pView, "WHERE", (n--)>0);
      sqlite3TreeViewExpr(pView, p->pWhere, 0);
      sqlite3TreeViewPop(pView);
    }
    if( p->pGroupBy ){
      sqlite3TreeViewExprList(pView, p->pGroupBy, (n--)>0, "GROUPBY");
    }
    if( p->pHaving ){
      sqlite3TreeViewItem(pView, "HAVING", (n--)>0);
      sqlite3TreeViewExpr(pView, p->pHaving, 0);
      sqlite3TreeViewPop(pView);
    }
    if( p->pOrderBy ){
      sqlite3TreeViewExprList(pView, p->pOrderBy, (n--)>0, "ORDERBY");
    }
    if( p->pLimit ){
      sqlite3TreeViewItem(pView, "LIMIT", (n--)>0);
      sqlite3TreeViewExpr(pView, p->pLimit, 0);
      sqlite3TreeViewPop(pView);
    }
    if( p->pOffset ){
      sqlite3TreeViewItem(pView, "OFFSET", (n--)>0);
      sqlite3TreeViewExpr(pView, p->pOffset, 0);
      sqlite3TreeViewPop(pView);
    }
    if( p->pPrior ){
      const char *zOp = "UNION";
      switch( p->op ){
        case TK_ALL:         zOp = "UNION ALL";  break;
        case TK_INTERSECT:   zOp = "INTERSECT";  break;
        case TK_EXCEPT:      zOp = "EXCEPT";     break;
      }
      sqlite3TreeViewItem(pView, zOp, 1);
    }
    p = p->pPrior;
  }while( p!=0 );
  sqlite3TreeViewPop(pView);
}

/*
** Generate a human-readable explanation of an expression tree.
*/
void sqlite3TreeViewExpr(TreeView *pView, const Expr *pExpr, u8 moreToFollow){
  const char *zBinOp = 0;   /* Binary operator */
  const char *zUniOp = 0;   /* Unary operator */
  char zFlgs[60];
  pView = sqlite3TreeViewPush(pView, moreToFollow);
  if( pExpr==0 ){
    sqlite3TreeViewLine(pView, "nil");
    sqlite3TreeViewPop(pView);
    return;
  }
  if( pExpr->flags ){
    if( ExprHasProperty(pExpr, EP_FromJoin) ){
      sqlite3_snprintf(sizeof(zFlgs),zFlgs,"  flags=0x%x iRJT=%d",
                       pExpr->flags, pExpr->iRightJoinTable);
    }else{
      sqlite3_snprintf(sizeof(zFlgs),zFlgs,"  flags=0x%x",pExpr->flags);
    }
  }else{
    zFlgs[0] = 0;
  }
  switch( pExpr->op ){
    case TK_AGG_COLUMN: {
      sqlite3TreeViewLine(pView, "AGG{%d:%d}%s",
            pExpr->iTable, pExpr->iColumn, zFlgs);
      break;
    }
    case TK_COLUMN: {
      if( pExpr->iTable<0 ){
        /* This only happens when coding check constraints */
        sqlite3TreeViewLine(pView, "COLUMN(%d)%s", pExpr->iColumn, zFlgs);
      }else{
        sqlite3TreeViewLine(pView, "{%d:%d}%s",
                             pExpr->iTable, pExpr->iColumn, zFlgs);
      }
      break;
    }
    case TK_INTEGER: {
      if( pExpr->flags & EP_IntValue ){
        sqlite3TreeViewLine(pView, "%d", pExpr->u.iValue);
      }else{
        sqlite3TreeViewLine(pView, "%s", pExpr->u.zToken);
      }
      break;
    }
#ifndef SQLITE_OMIT_FLOATING_POINT
    case TK_FLOAT: {
      sqlite3TreeViewLine(pView,"%s", pExpr->u.zToken);
      break;
    }
#endif
    case TK_STRING: {
      sqlite3TreeViewLine(pView,"%Q", pExpr->u.zToken);
      break;
    }
    case TK_NULL: {
      sqlite3TreeViewLine(pView,"NULL");
      break;
    }
#ifndef SQLITE_OMIT_BLOB_LITERAL
    case TK_BLOB: {
      sqlite3TreeViewLine(pView,"%s", pExpr->u.zToken);
      break;
    }
#endif
    case TK_VARIABLE: {
      sqlite3TreeViewLine(pView,"VARIABLE(%s,%d)",
                          pExpr->u.zToken, pExpr->iColumn);
      break;
    }
    case TK_REGISTER: {
      sqlite3TreeViewLine(pView,"REGISTER(%d)", pExpr->iTable);
      break;
    }
    case TK_ID: {
      sqlite3TreeViewLine(pView,"ID \"%w\"", pExpr->u.zToken);
      break;
    }
#ifndef SQLITE_OMIT_CAST
    case TK_CAST: {
      /* Expressions of the form:   CAST(pLeft AS token) */
      sqlite3TreeViewLine(pView,"CAST %Q", pExpr->u.zToken);
      sqlite3TreeViewExpr(pView, pExpr->pLeft, 0);
      break;
    }
#endif /* SQLITE_OMIT_CAST */
    case TK_LT:      zBinOp = "LT";     break;
    case TK_LE:      zBinOp = "LE";     break;
    case TK_GT:      zBinOp = "GT";     break;
    case TK_GE:      zBinOp = "GE";     break;
    case TK_NE:      zBinOp = "NE";     break;
    case TK_EQ:      zBinOp = "EQ";     break;
    case TK_IS:      zBinOp = "IS";     break;
    case TK_ISNOT:   zBinOp = "ISNOT";  break;
    case TK_AND:     zBinOp = "AND";    break;
    case TK_OR:      zBinOp = "OR";     break;
    case TK_PLUS:    zBinOp = "ADD";    break;
    case TK_STAR:    zBinOp = "MUL";    break;
    case TK_MINUS:   zBinOp = "SUB";    break;
    case TK_REM:     zBinOp = "REM";    break;
    case TK_BITAND:  zBinOp = "BITAND"; break;
    case TK_BITOR:   zBinOp = "BITOR";  break;
    case TK_SLASH:   zBinOp = "DIV";    break;
    case TK_LSHIFT:  zBinOp = "LSHIFT"; break;
    case TK_RSHIFT:  zBinOp = "RSHIFT"; break;
    case TK_CONCAT:  zBinOp = "CONCAT"; break;
    case TK_DOT:     zBinOp = "DOT";    break;

    case TK_UMINUS:  zUniOp = "UMINUS"; break;
    case TK_UPLUS:   zUniOp = "UPLUS";  break;
    case TK_BITNOT:  zUniOp = "BITNOT"; break;
    case TK_NOT:     zUniOp = "NOT";    break;
    case TK_ISNULL:  zUniOp = "ISNULL"; break;
    case TK_NOTNULL: zUniOp = "NOTNULL"; break;

    case TK_SPAN: {
      sqlite3TreeViewLine(pView, "SPAN %Q", pExpr->u.zToken);
      sqlite3TreeViewExpr(pView, pExpr->pLeft, 0);
      break;
    }

    case TK_COLLATE: {
      sqlite3TreeViewLine(pView, "COLLATE %Q", pExpr->u.zToken);
      sqlite3TreeViewExpr(pView, pExpr->pLeft, 0);
      break;
    }

    case TK_AGG_FUNCTION:
    case TK_FUNCTION: {
      ExprList *pFarg;       /* List of function arguments */
      if( ExprHasProperty(pExpr, EP_TokenOnly) ){
        pFarg = 0;
      }else{
        pFarg = pExpr->x.pList;
      }
      if( pExpr->op==TK_AGG_FUNCTION ){
        sqlite3TreeViewLine(pView, "AGG_FUNCTION%d %Q",
                             pExpr->op2, pExpr->u.zToken);
      }else{
        sqlite3TreeViewLine(pView, "FUNCTION %Q", pExpr->u.zToken);
      }
      if( pFarg ){
        sqlite3TreeViewExprList(pView, pFarg, 0, 0);
      }
      break;
    }
#ifndef SQLITE_OMIT_SUBQUERY
    case TK_EXISTS: {
      sqlite3TreeViewLine(pView, "EXISTS-expr flags=0x%x", pExpr->flags);
      sqlite3TreeViewSelect(pView, pExpr->x.pSelect, 0);
      break;
    }
    case TK_SELECT: {
      sqlite3TreeViewLine(pView, "SELECT-expr flags=0x%x", pExpr->flags);
      sqlite3TreeViewSelect(pView, pExpr->x.pSelect, 0);
      break;
    }
    case TK_IN: {
      sqlite3TreeViewLine(pView, "IN flags=0x%x", pExpr->flags);
      sqlite3TreeViewExpr(pView, pExpr->pLeft, 1);
      if( ExprHasProperty(pExpr, EP_xIsSelect) ){
        sqlite3TreeViewSelect(pView, pExpr->x.pSelect, 0);
      }else{
        sqlite3TreeViewExprList(pView, pExpr->x.pList, 0, 0);
      }
      break;
    }
#endif /* SQLITE_OMIT_SUBQUERY */

    /*
    **    x BETWEEN y AND z
    **
    ** This is equivalent to
    **
    **    x>=y AND x<=z
    **
    ** X is stored in pExpr->pLeft.
    ** Y is stored in pExpr->pList->a[0].pExpr.
    ** Z is stored in pExpr->pList->a[1].pExpr.
    */
    case TK_BETWEEN: {
      Expr *pX = pExpr->pLeft;
      Expr *pY = pExpr->x.pList->a[0].pExpr;
      Expr *pZ = pExpr->x.pList->a[1].pExpr;
      sqlite3TreeViewLine(pView, "BETWEEN");
      sqlite3TreeViewExpr(pView, pX, 1);
      sqlite3TreeViewExpr(pView, pY, 1);
      sqlite3TreeViewExpr(pView, pZ, 0);
      break;
    }
    case TK_TRIGGER: {
      /* If the opcode is TK_TRIGGER, then the expression is a reference
      ** to a column in the new.* or old.* pseudo-tables available to
      ** trigger programs. In this case Expr.iTable is set to 1 for the
      ** new.* pseudo-table, or 0 for the old.* pseudo-table. Expr.iColumn
      ** is set to the column of the pseudo-table to read, or to -1 to
      ** read the rowid field.
      */
      sqlite3TreeViewLine(pView, "%s(%d)", 
          pExpr->iTable ? "NEW" : "OLD", pExpr->iColumn);
      break;
    }
    case TK_CASE: {
      sqlite3TreeViewLine(pView, "CASE");
      sqlite3TreeViewExpr(pView, pExpr->pLeft, 1);
      sqlite3TreeViewExprList(pView, pExpr->x.pList, 0, 0);
      break;
    }
#ifndef SQLITE_OMIT_TRIGGER
    case TK_RAISE: {
      const char *zType = "unk";
      switch( pExpr->affinity ){
        case OE_Rollback:   zType = "rollback";  break;
        case OE_Abort:      zType = "abort";     break;
        case OE_Fail:       zType = "fail";      break;
        case OE_Ignore:     zType = "ignore";    break;
      }
      sqlite3TreeViewLine(pView, "RAISE %s(%Q)", zType, pExpr->u.zToken);
      break;
    }
#endif
    case TK_MATCH: {
      sqlite3TreeViewLine(pView, "MATCH {%d:%d}%s",
                          pExpr->iTable, pExpr->iColumn, zFlgs);
      sqlite3TreeViewExpr(pView, pExpr->pRight, 0);
      break;
    }
    case TK_VECTOR: {
      sqlite3TreeViewBareExprList(pView, pExpr->x.pList, "VECTOR");
      break;
    }
    case TK_SELECT_COLUMN: {
      sqlite3TreeViewLine(pView, "SELECT-COLUMN %d", pExpr->iColumn);
      sqlite3TreeViewSelect(pView, pExpr->pLeft->x.pSelect, 0);
      break;
    }
    case TK_IF_NULL_ROW: {
      sqlite3TreeViewLine(pView, "IF-NULL-ROW %d", pExpr->iTable);
      sqlite3TreeViewExpr(pView, pExpr->pLeft, 0);
      break;
    }
    default: {
      sqlite3TreeViewLine(pView, "op=%d", pExpr->op);
      break;
    }
  }
  if( zBinOp ){
    sqlite3TreeViewLine(pView, "%s%s", zBinOp, zFlgs);
    sqlite3TreeViewExpr(pView, pExpr->pLeft, 1);
    sqlite3TreeViewExpr(pView, pExpr->pRight, 0);
  }else if( zUniOp ){
    sqlite3TreeViewLine(pView, "%s%s", zUniOp, zFlgs);
    sqlite3TreeViewExpr(pView, pExpr->pLeft, 0);
  }
  sqlite3TreeViewPop(pView);
}


/*
** Generate a human-readable explanation of an expression list.
*/
void sqlite3TreeViewBareExprList(
  TreeView *pView,
  const ExprList *pList,
  const char *zLabel
){
  if( zLabel==0 || zLabel[0]==0 ) zLabel = "LIST";
  if( pList==0 ){
    sqlite3TreeViewLine(pView, "%s (empty)", zLabel);
  }else{
    int i;
    sqlite3TreeViewLine(pView, "%s", zLabel);
    for(i=0; i<pList->nExpr; i++){
      int j = pList->a[i].u.x.iOrderByCol;
      if( j ){
        sqlite3TreeViewPush(pView, 0);
        sqlite3TreeViewLine(pView, "iOrderByCol=%d", j);
      }
      sqlite3TreeViewExpr(pView, pList->a[i].pExpr, i<pList->nExpr-1);
      if( j ) sqlite3TreeViewPop(pView);
    }
  }
}
void sqlite3TreeViewExprList(
  TreeView *pView,
  const ExprList *pList,
  u8 moreToFollow,
  const char *zLabel
){
  pView = sqlite3TreeViewPush(pView, moreToFollow);
  sqlite3TreeViewBareExprList(pView, pList, zLabel);
  sqlite3TreeViewPop(pView);
}

#endif /* SQLITE_DEBUG */
