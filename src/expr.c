/*
** 2001 September 15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This file contains routines used for analyzing expressions and
** for generating VDBE code that evaluates expressions in SQLite.
*/
#include "sqliteInt.h"

/* Forward declarations */
static void exprCodeBetween(Parse*,Expr*,int,void(*)(Parse*,Expr*,int,int),int);
static int exprCodeVector(Parse *pParse, Expr *p, int *piToFree);

/*
** Return the affinity character for a single column of a table.
*/
char sqlite3TableColumnAffinity(Table *pTab, int iCol){
  assert( iCol<pTab->nCol );
  return iCol>=0 ? pTab->aCol[iCol].affinity : SQLITE_AFF_INTEGER;
}

/*
** Return the 'affinity' of the expression pExpr if any.
**
** If pExpr is a column, a reference to a column via an 'AS' alias,
** or a sub-select with a column as the return value, then the 
** affinity of that column is returned. Otherwise, 0x00 is returned,
** indicating no affinity for the expression.
**
** i.e. the WHERE clause expressions in the following statements all
** have an affinity:
**
** CREATE TABLE t1(a);
** SELECT * FROM t1 WHERE a;
** SELECT a AS b FROM t1 WHERE b;
** SELECT * FROM t1 WHERE (select a from t1);
*/
char sqlite3ExprAffinity(Expr *pExpr){
  int op;
  pExpr = sqlite3ExprSkipCollate(pExpr);
  if( pExpr->flags & EP_Generic ) return 0;
  op = pExpr->op;
  if( op==TK_SELECT ){
    assert( pExpr->flags&EP_xIsSelect );
    return sqlite3ExprAffinity(pExpr->x.pSelect->pEList->a[0].pExpr);
  }
  if( op==TK_REGISTER ) op = pExpr->op2;
#ifndef SQLITE_OMIT_CAST
  if( op==TK_CAST ){
    assert( !ExprHasProperty(pExpr, EP_IntValue) );
    return sqlite3AffinityType(pExpr->u.zToken, 0);
  }
#endif
  if( (op==TK_AGG_COLUMN || op==TK_COLUMN) && pExpr->pTab ){
    return sqlite3TableColumnAffinity(pExpr->pTab, pExpr->iColumn);
  }
  if( op==TK_SELECT_COLUMN ){
    assert( pExpr->pLeft->flags&EP_xIsSelect );
    return sqlite3ExprAffinity(
        pExpr->pLeft->x.pSelect->pEList->a[pExpr->iColumn].pExpr
    );
  }
  return pExpr->affinity;
}

/*
** Set the collating sequence for expression pExpr to be the collating
** sequence named by pToken.   Return a pointer to a new Expr node that
** implements the COLLATE operator.
**
** If a memory allocation error occurs, that fact is recorded in pParse->db
** and the pExpr parameter is returned unchanged.
*/
Expr *sqlite3ExprAddCollateToken(
  Parse *pParse,           /* Parsing context */
  Expr *pExpr,             /* Add the "COLLATE" clause to this expression */
  const Token *pCollName,  /* Name of collating sequence */
  int dequote              /* True to dequote pCollName */
){
  if( pCollName->n>0 ){
    Expr *pNew = sqlite3ExprAlloc(pParse->db, TK_COLLATE, pCollName, dequote);
    if( pNew ){
      pNew->pLeft = pExpr;
      pNew->flags |= EP_Collate|EP_Skip;
      pExpr = pNew;
    }
  }
  return pExpr;
}
Expr *sqlite3ExprAddCollateString(Parse *pParse, Expr *pExpr, const char *zC){
  Token s;
  assert( zC!=0 );
  sqlite3TokenInit(&s, (char*)zC);
  return sqlite3ExprAddCollateToken(pParse, pExpr, &s, 0);
}

/*
** Skip over any TK_COLLATE operators and any unlikely()
** or likelihood() function at the root of an expression.
*/
Expr *sqlite3ExprSkipCollate(Expr *pExpr){
  while( pExpr && ExprHasProperty(pExpr, EP_Skip) ){
    if( ExprHasProperty(pExpr, EP_Unlikely) ){
      assert( !ExprHasProperty(pExpr, EP_xIsSelect) );
      assert( pExpr->x.pList->nExpr>0 );
      assert( pExpr->op==TK_FUNCTION );
      pExpr = pExpr->x.pList->a[0].pExpr;
    }else{
      assert( pExpr->op==TK_COLLATE );
      pExpr = pExpr->pLeft;
    }
  }   
  return pExpr;
}

/*
** Return the collation sequence for the expression pExpr. If
** there is no defined collating sequence, return NULL.
**
** The collating sequence might be determined by a COLLATE operator
** or by the presence of a column with a defined collating sequence.
** COLLATE operators take first precedence.  Left operands take
** precedence over right operands.
*/
CollSeq *sqlite3ExprCollSeq(Parse *pParse, Expr *pExpr){
  sqlite3 *db = pParse->db;
  CollSeq *pColl = 0;
  Expr *p = pExpr;
  while( p ){
    int op = p->op;
    if( p->flags & EP_Generic ) break;
    if( op==TK_CAST || op==TK_UPLUS ){
      p = p->pLeft;
      continue;
    }
    if( op==TK_COLLATE || (op==TK_REGISTER && p->op2==TK_COLLATE) ){
      pColl = sqlite3GetCollSeq(pParse, ENC(db), 0, p->u.zToken);
      break;
    }
    if( (op==TK_AGG_COLUMN || op==TK_COLUMN
          || op==TK_REGISTER || op==TK_TRIGGER)
     && p->pTab!=0
    ){
      /* op==TK_REGISTER && p->pTab!=0 happens when pExpr was originally
      ** a TK_COLUMN but was previously evaluated and cached in a register */
      int j = p->iColumn;
      if( j>=0 ){
        const char *zColl = p->pTab->aCol[j].zColl;
        pColl = sqlite3FindCollSeq(db, ENC(db), zColl, 0);
      }
      break;
    }
    if( p->flags & EP_Collate ){
      if( p->pLeft && (p->pLeft->flags & EP_Collate)!=0 ){
        p = p->pLeft;
      }else{
        Expr *pNext  = p->pRight;
        /* The Expr.x union is never used at the same time as Expr.pRight */
        assert( p->x.pList==0 || p->pRight==0 );
        /* p->flags holds EP_Collate and p->pLeft->flags does not.  And
        ** p->x.pSelect cannot.  So if p->x.pLeft exists, it must hold at
        ** least one EP_Collate. Thus the following two ALWAYS. */
        if( p->x.pList!=0 && ALWAYS(!ExprHasProperty(p, EP_xIsSelect)) ){
          int i;
          for(i=0; ALWAYS(i<p->x.pList->nExpr); i++){
            if( ExprHasProperty(p->x.pList->a[i].pExpr, EP_Collate) ){
              pNext = p->x.pList->a[i].pExpr;
              break;
            }
          }
        }
        p = pNext;
      }
    }else{
      break;
    }
  }
  if( sqlite3CheckCollSeq(pParse, pColl) ){ 
    pColl = 0;
  }
  return pColl;
}

/*
** pExpr is an operand of a comparison operator.  aff2 is the
** type affinity of the other operand.  This routine returns the
** type affinity that should be used for the comparison operator.
*/
char sqlite3CompareAffinity(Expr *pExpr, char aff2){
  char aff1 = sqlite3ExprAffinity(pExpr);
  if( aff1 && aff2 ){
    /* Both sides of the comparison are columns. If one has numeric
    ** affinity, use that. Otherwise use no affinity.
    */
    if( sqlite3IsNumericAffinity(aff1) || sqlite3IsNumericAffinity(aff2) ){
      return SQLITE_AFF_NUMERIC;
    }else{
      return SQLITE_AFF_BLOB;
    }
  }else if( !aff1 && !aff2 ){
    /* Neither side of the comparison is a column.  Compare the
    ** results directly.
    */
    return SQLITE_AFF_BLOB;
  }else{
    /* One side is a column, the other is not. Use the columns affinity. */
    assert( aff1==0 || aff2==0 );
    return (aff1 + aff2);
  }
}

/*
** pExpr is a comparison operator.  Return the type affinity that should
** be applied to both operands prior to doing the comparison.
*/
static char comparisonAffinity(Expr *pExpr){
  char aff;
  assert( pExpr->op==TK_EQ || pExpr->op==TK_IN || pExpr->op==TK_LT ||
          pExpr->op==TK_GT || pExpr->op==TK_GE || pExpr->op==TK_LE ||
          pExpr->op==TK_NE || pExpr->op==TK_IS || pExpr->op==TK_ISNOT );
  assert( pExpr->pLeft );
  aff = sqlite3ExprAffinity(pExpr->pLeft);
  if( pExpr->pRight ){
    aff = sqlite3CompareAffinity(pExpr->pRight, aff);
  }else if( ExprHasProperty(pExpr, EP_xIsSelect) ){
    aff = sqlite3CompareAffinity(pExpr->x.pSelect->pEList->a[0].pExpr, aff);
  }else if( aff==0 ){
    aff = SQLITE_AFF_BLOB;
  }
  return aff;
}

/*
** pExpr is a comparison expression, eg. '=', '<', IN(...) etc.
** idx_affinity is the affinity of an indexed column. Return true
** if the index with affinity idx_affinity may be used to implement
** the comparison in pExpr.
*/
int sqlite3IndexAffinityOk(Expr *pExpr, char idx_affinity){
  char aff = comparisonAffinity(pExpr);
  switch( aff ){
    case SQLITE_AFF_BLOB:
      return 1;
    case SQLITE_AFF_TEXT:
      return idx_affinity==SQLITE_AFF_TEXT;
    default:
      return sqlite3IsNumericAffinity(idx_affinity);
  }
}

/*
** Return the P5 value that should be used for a binary comparison
** opcode (OP_Eq, OP_Ge etc.) used to compare pExpr1 and pExpr2.
*/
static u8 binaryCompareP5(Expr *pExpr1, Expr *pExpr2, int jumpIfNull){
  u8 aff = (char)sqlite3ExprAffinity(pExpr2);
  aff = (u8)sqlite3CompareAffinity(pExpr1, aff) | (u8)jumpIfNull;
  return aff;
}

/*
** Return a pointer to the collation sequence that should be used by
** a binary comparison operator comparing pLeft and pRight.
**
** If the left hand expression has a collating sequence type, then it is
** used. Otherwise the collation sequence for the right hand expression
** is used, or the default (BINARY) if neither expression has a collating
** type.
**
** Argument pRight (but not pLeft) may be a null pointer. In this case,
** it is not considered.
*/
CollSeq *sqlite3BinaryCompareCollSeq(
  Parse *pParse, 
  Expr *pLeft, 
  Expr *pRight
){
  CollSeq *pColl;
  assert( pLeft );
  if( pLeft->flags & EP_Collate ){
    pColl = sqlite3ExprCollSeq(pParse, pLeft);
  }else if( pRight && (pRight->flags & EP_Collate)!=0 ){
    pColl = sqlite3ExprCollSeq(pParse, pRight);
  }else{
    pColl = sqlite3ExprCollSeq(pParse, pLeft);
    if( !pColl ){
      pColl = sqlite3ExprCollSeq(pParse, pRight);
    }
  }
  return pColl;
}

/*
** Generate code for a comparison operator.
*/
static int codeCompare(
  Parse *pParse,    /* The parsing (and code generating) context */
  Expr *pLeft,      /* The left operand */
  Expr *pRight,     /* The right operand */
  int opcode,       /* The comparison opcode */
  int in1, int in2, /* Register holding operands */
  int dest,         /* Jump here if true.  */
  int jumpIfNull    /* If true, jump if either operand is NULL */
){
  int p5;
  int addr;
  CollSeq *p4;

  p4 = sqlite3BinaryCompareCollSeq(pParse, pLeft, pRight);
  p5 = binaryCompareP5(pLeft, pRight, jumpIfNull);
  addr = sqlite3VdbeAddOp4(pParse->pVdbe, opcode, in2, dest, in1,
                           (void*)p4, P4_COLLSEQ);
  sqlite3VdbeChangeP5(pParse->pVdbe, (u8)p5);
  return addr;
}

/*
** Return true if expression pExpr is a vector, or false otherwise.
**
** A vector is defined as any expression that results in two or more
** columns of result.  Every TK_VECTOR node is an vector because the
** parser will not generate a TK_VECTOR with fewer than two entries.
** But a TK_SELECT might be either a vector or a scalar. It is only
** considered a vector if it has two or more result columns.
*/
int sqlite3ExprIsVector(Expr *pExpr){
  return sqlite3ExprVectorSize(pExpr)>1;
}

/*
** If the expression passed as the only argument is of type TK_VECTOR 
** return the number of expressions in the vector. Or, if the expression
** is a sub-select, return the number of columns in the sub-select. For
** any other type of expression, return 1.
*/
int sqlite3ExprVectorSize(Expr *pExpr){
  u8 op = pExpr->op;
  if( op==TK_REGISTER ) op = pExpr->op2;
  if( op==TK_VECTOR ){
    return pExpr->x.pList->nExpr;
  }else if( op==TK_SELECT ){
    return pExpr->x.pSelect->pEList->nExpr;
  }else{
    return 1;
  }
}

/*
** Return a pointer to a subexpression of pVector that is the i-th
** column of the vector (numbered starting with 0).  The caller must
** ensure that i is within range.
**
** If pVector is really a scalar (and "scalar" here includes subqueries
** that return a single column!) then return pVector unmodified.
**
** pVector retains ownership of the returned subexpression.
**
** If the vector is a (SELECT ...) then the expression returned is
** just the expression for the i-th term of the result set, and may
** not be ready for evaluation because the table cursor has not yet
** been positioned.
*/
Expr *sqlite3VectorFieldSubexpr(Expr *pVector, int i){
  assert( i<sqlite3ExprVectorSize(pVector) );
  if( sqlite3ExprIsVector(pVector) ){
    assert( pVector->op2==0 || pVector->op==TK_REGISTER );
    if( pVector->op==TK_SELECT || pVector->op2==TK_SELECT ){
      return pVector->x.pSelect->pEList->a[i].pExpr;
    }else{
      return pVector->x.pList->a[i].pExpr;
    }
  }
  return pVector;
}

/*
** Compute and return a new Expr object which when passed to
** sqlite3ExprCode() will generate all necessary code to compute
** the iField-th column of the vector expression pVector.
**
** It is ok for pVector to be a scalar (as long as iField==0).  
** In that case, this routine works like sqlite3ExprDup().
**
** The caller owns the returned Expr object and is responsible for
** ensuring that the returned value eventually gets freed.
**
** The caller retains ownership of pVector.  If pVector is a TK_SELECT,
** then the returned object will reference pVector and so pVector must remain
** valid for the life of the returned object.  If pVector is a TK_VECTOR
** or a scalar expression, then it can be deleted as soon as this routine
** returns.
**
** A trick to cause a TK_SELECT pVector to be deleted together with
** the returned Expr object is to attach the pVector to the pRight field
** of the returned TK_SELECT_COLUMN Expr object.
*/
Expr *sqlite3ExprForVectorField(
  Parse *pParse,       /* Parsing context */
  Expr *pVector,       /* The vector.  List of expressions or a sub-SELECT */
  int iField           /* Which column of the vector to return */
){
  Expr *pRet;
  if( pVector->op==TK_SELECT ){
    assert( pVector->flags & EP_xIsSelect );
    /* The TK_SELECT_COLUMN Expr node:
    **
    ** pLeft:           pVector containing TK_SELECT.  Not deleted.
    ** pRight:          not used.  But recursively deleted.
    ** iColumn:         Index of a column in pVector
    ** iTable:          0 or the number of columns on the LHS of an assignment
    ** pLeft->iTable:   First in an array of register holding result, or 0
    **                  if the result is not yet computed.
    **
    ** sqlite3ExprDelete() specifically skips the recursive delete of
    ** pLeft on TK_SELECT_COLUMN nodes.  But pRight is followed, so pVector
    ** can be attached to pRight to cause this node to take ownership of
    ** pVector.  Typically there will be multiple TK_SELECT_COLUMN nodes
    ** with the same pLeft pointer to the pVector, but only one of them
    ** will own the pVector.
    */
    pRet = sqlite3PExpr(pParse, TK_SELECT_COLUMN, 0, 0);
    if( pRet ){
      pRet->iColumn = iField;
      pRet->pLeft = pVector;
    }
    assert( pRet==0 || pRet->iTable==0 );
  }else{
    if( pVector->op==TK_VECTOR ) pVector = pVector->x.pList->a[iField].pExpr;
    pRet = sqlite3ExprDup(pParse->db, pVector, 0);
  }
  return pRet;
}

/*
** If expression pExpr is of type TK_SELECT, generate code to evaluate
** it. Return the register in which the result is stored (or, if the 
** sub-select returns more than one column, the first in an array
** of registers in which the result is stored).
**
** If pExpr is not a TK_SELECT expression, return 0.
*/
static int exprCodeSubselect(Parse *pParse, Expr *pExpr){
  int reg = 0;
#ifndef SQLITE_OMIT_SUBQUERY
  if( pExpr->op==TK_SELECT ){
    reg = sqlite3CodeSubselect(pParse, pExpr, 0, 0);
  }
#endif
  return reg;
}

/*
** Argument pVector points to a vector expression - either a TK_VECTOR
** or TK_SELECT that returns more than one column. This function returns
** the register number of a register that contains the value of
** element iField of the vector.
**
** If pVector is a TK_SELECT expression, then code for it must have 
** already been generated using the exprCodeSubselect() routine. In this
** case parameter regSelect should be the first in an array of registers
** containing the results of the sub-select. 
**
** If pVector is of type TK_VECTOR, then code for the requested field
** is generated. In this case (*pRegFree) may be set to the number of
** a temporary register to be freed by the caller before returning.
**
** Before returning, output parameter (*ppExpr) is set to point to the
** Expr object corresponding to element iElem of the vector.
*/
static int exprVectorRegister(
  Parse *pParse,                  /* Parse context */
  Expr *pVector,                  /* Vector to extract element from */
  int iField,                     /* Field to extract from pVector */
  int regSelect,                  /* First in array of registers */
  Expr **ppExpr,                  /* OUT: Expression element */
  int *pRegFree                   /* OUT: Temp register to free */
){
  u8 op = pVector->op;
  assert( op==TK_VECTOR || op==TK_REGISTER || op==TK_SELECT );
  if( op==TK_REGISTER ){
    *ppExpr = sqlite3VectorFieldSubexpr(pVector, iField);
    return pVector->iTable+iField;
  }
  if( op==TK_SELECT ){
    *ppExpr = pVector->x.pSelect->pEList->a[iField].pExpr;
     return regSelect+iField;
  }
  *ppExpr = pVector->x.pList->a[iField].pExpr;
  return sqlite3ExprCodeTemp(pParse, *ppExpr, pRegFree);
}

/*
** Expression pExpr is a comparison between two vector values. Compute
** the result of the comparison (1, 0, or NULL) and write that
** result into register dest.
**
** The caller must satisfy the following preconditions:
**
**    if pExpr->op==TK_IS:      op==TK_EQ and p5==SQLITE_NULLEQ
**    if pExpr->op==TK_ISNOT:   op==TK_NE and p5==SQLITE_NULLEQ
**    otherwise:                op==pExpr->op and p5==0
*/
static void codeVectorCompare(
  Parse *pParse,        /* Code generator context */
  Expr *pExpr,          /* The comparison operation */
  int dest,             /* Write results into this register */
  u8 op,                /* Comparison operator */
  u8 p5                 /* SQLITE_NULLEQ or zero */
){
  Vdbe *v = pParse->pVdbe;
  Expr *pLeft = pExpr->pLeft;
  Expr *pRight = pExpr->pRight;
  int nLeft = sqlite3ExprVectorSize(pLeft);
  int i;
  int regLeft = 0;
  int regRight = 0;
  u8 opx = op;
  int addrDone = sqlite3VdbeMakeLabel(v);

  if( nLeft!=sqlite3ExprVectorSize(pRight) ){
    sqlite3ErrorMsg(pParse, "row value misused");
    return;
  }
  assert( pExpr->op==TK_EQ || pExpr->op==TK_NE 
       || pExpr->op==TK_IS || pExpr->op==TK_ISNOT 
       || pExpr->op==TK_LT || pExpr->op==TK_GT 
       || pExpr->op==TK_LE || pExpr->op==TK_GE 
  );
  assert( pExpr->op==op || (pExpr->op==TK_IS && op==TK_EQ)
            || (pExpr->op==TK_ISNOT && op==TK_NE) );
  assert( p5==0 || pExpr->op!=op );
  assert( p5==SQLITE_NULLEQ || pExpr->op==op );

  p5 |= SQLITE_STOREP2;
  if( opx==TK_LE ) opx = TK_LT;
  if( opx==TK_GE ) opx = TK_GT;

  regLeft = exprCodeSubselect(pParse, pLeft);
  regRight = exprCodeSubselect(pParse, pRight);

  for(i=0; 1 /*Loop exits by "break"*/; i++){
    int regFree1 = 0, regFree2 = 0;
    Expr *pL, *pR; 
    int r1, r2;
    assert( i>=0 && i<nLeft );
    if( i>0 ) sqlite3ExprCachePush(pParse);
    r1 = exprVectorRegister(pParse, pLeft, i, regLeft, &pL, &regFree1);
    r2 = exprVectorRegister(pParse, pRight, i, regRight, &pR, &regFree2);
    codeCompare(pParse, pL, pR, opx, r1, r2, dest, p5);
    testcase(op==OP_Lt); VdbeCoverageIf(v,op==OP_Lt);
    testcase(op==OP_Le); VdbeCoverageIf(v,op==OP_Le);
    testcase(op==OP_Gt); VdbeCoverageIf(v,op==OP_Gt);
    testcase(op==OP_Ge); VdbeCoverageIf(v,op==OP_Ge);
    testcase(op==OP_Eq); VdbeCoverageIf(v,op==OP_Eq);
    testcase(op==OP_Ne); VdbeCoverageIf(v,op==OP_Ne);
    sqlite3ReleaseTempReg(pParse, regFree1);
    sqlite3ReleaseTempReg(pParse, regFree2);
    if( i>0 ) sqlite3ExprCachePop(pParse);
    if( i==nLeft-1 ){
      break;
    }
    if( opx==TK_EQ ){
      sqlite3VdbeAddOp2(v, OP_IfNot, dest, addrDone); VdbeCoverage(v);
      p5 |= SQLITE_KEEPNULL;
    }else if( opx==TK_NE ){
      sqlite3VdbeAddOp2(v, OP_If, dest, addrDone); VdbeCoverage(v);
      p5 |= SQLITE_KEEPNULL;
    }else{
      assert( op==TK_LT || op==TK_GT || op==TK_LE || op==TK_GE );
      sqlite3VdbeAddOp2(v, OP_ElseNotEq, 0, addrDone);
      VdbeCoverageIf(v, op==TK_LT);
      VdbeCoverageIf(v, op==TK_GT);
      VdbeCoverageIf(v, op==TK_LE);
      VdbeCoverageIf(v, op==TK_GE);
      if( i==nLeft-2 ) opx = op;
    }
  }
  sqlite3VdbeResolveLabel(v, addrDone);
}

#if SQLITE_MAX_EXPR_DEPTH>0
/*
** Check that argument nHeight is less than or equal to the maximum
** expression depth allowed. If it is not, leave an error message in
** pParse.
*/
int sqlite3ExprCheckHeight(Parse *pParse, int nHeight){
  int rc = SQLITE_OK;
  int mxHeight = pParse->db->aLimit[SQLITE_LIMIT_EXPR_DEPTH];
  if( nHeight>mxHeight ){
    sqlite3ErrorMsg(pParse, 
       "Expression tree is too large (maximum depth %d)", mxHeight
    );
    rc = SQLITE_ERROR;
  }
  return rc;
}

/* The following three functions, heightOfExpr(), heightOfExprList()
** and heightOfSelect(), are used to determine the maximum height
** of any expression tree referenced by the structure passed as the
** first argument.
**
** If this maximum height is greater than the current value pointed
** to by pnHeight, the second parameter, then set *pnHeight to that
** value.
*/
static void heightOfExpr(Expr *p, int *pnHeight){
  if( p ){
    if( p->nHeight>*pnHeight ){
      *pnHeight = p->nHeight;
    }
  }
}
static void heightOfExprList(ExprList *p, int *pnHeight){
  if( p ){
    int i;
    for(i=0; i<p->nExpr; i++){
      heightOfExpr(p->a[i].pExpr, pnHeight);
    }
  }
}
static void heightOfSelect(Select *p, int *pnHeight){
  if( p ){
    heightOfExpr(p->pWhere, pnHeight);
    heightOfExpr(p->pHaving, pnHeight);
    heightOfExpr(p->pLimit, pnHeight);
    heightOfExpr(p->pOffset, pnHeight);
    heightOfExprList(p->pEList, pnHeight);
    heightOfExprList(p->pGroupBy, pnHeight);
    heightOfExprList(p->pOrderBy, pnHeight);
    heightOfSelect(p->pPrior, pnHeight);
  }
}

/*
** Set the Expr.nHeight variable in the structure passed as an 
** argument. An expression with no children, Expr.pList or 
** Expr.pSelect member has a height of 1. Any other expression
** has a height equal to the maximum height of any other 
** referenced Expr plus one.
**
** Also propagate EP_Propagate flags up from Expr.x.pList to Expr.flags,
** if appropriate.
*/
static void exprSetHeight(Expr *p){
  int nHeight = 0;
  heightOfExpr(p->pLeft, &nHeight);
  heightOfExpr(p->pRight, &nHeight);
  if( ExprHasProperty(p, EP_xIsSelect) ){
    heightOfSelect(p->x.pSelect, &nHeight);
  }else if( p->x.pList ){
    heightOfExprList(p->x.pList, &nHeight);
    p->flags |= EP_Propagate & sqlite3ExprListFlags(p->x.pList);
  }
  p->nHeight = nHeight + 1;
}

/*
** Set the Expr.nHeight variable using the exprSetHeight() function. If
** the height is greater than the maximum allowed expression depth,
** leave an error in pParse.
**
** Also propagate all EP_Propagate flags from the Expr.x.pList into
** Expr.flags. 
*/
void sqlite3ExprSetHeightAndFlags(Parse *pParse, Expr *p){
  if( pParse->nErr ) return;
  exprSetHeight(p);
  sqlite3ExprCheckHeight(pParse, p->nHeight);
}

/*
** Return the maximum height of any expression tree referenced
** by the select statement passed as an argument.
*/
int sqlite3SelectExprHeight(Select *p){
  int nHeight = 0;
  heightOfSelect(p, &nHeight);
  return nHeight;
}
#else /* ABOVE:  Height enforcement enabled.  BELOW: Height enforcement off */
/*
** Propagate all EP_Propagate flags from the Expr.x.pList into
** Expr.flags. 
*/
void sqlite3ExprSetHeightAndFlags(Parse *pParse, Expr *p){
  if( p && p->x.pList && !ExprHasProperty(p, EP_xIsSelect) ){
    p->flags |= EP_Propagate & sqlite3ExprListFlags(p->x.pList);
  }
}
#define exprSetHeight(y)
#endif /* SQLITE_MAX_EXPR_DEPTH>0 */

/*
** This routine is the core allocator for Expr nodes.
**
** Construct a new expression node and return a pointer to it.  Memory
** for this node and for the pToken argument is a single allocation
** obtained from sqlite3DbMalloc().  The calling function
** is responsible for making sure the node eventually gets freed.
**
** If dequote is true, then the token (if it exists) is dequoted.
** If dequote is false, no dequoting is performed.  The deQuote
** parameter is ignored if pToken is NULL or if the token does not
** appear to be quoted.  If the quotes were of the form "..." (double-quotes)
** then the EP_DblQuoted flag is set on the expression node.
**
** Special case:  If op==TK_INTEGER and pToken points to a string that
** can be translated into a 32-bit integer, then the token is not
** stored in u.zToken.  Instead, the integer values is written
** into u.iValue and the EP_IntValue flag is set.  No extra storage
** is allocated to hold the integer text and the dequote flag is ignored.
*/
Expr *sqlite3ExprAlloc(
  sqlite3 *db,            /* Handle for sqlite3DbMallocRawNN() */
  int op,                 /* Expression opcode */
  const Token *pToken,    /* Token argument.  Might be NULL */
  int dequote             /* True to dequote */
){
  Expr *pNew;
  int nExtra = 0;
  int iValue = 0;

  assert( db!=0 );
  if( pToken ){
    if( op!=TK_INTEGER || pToken->z==0
          || sqlite3GetInt32(pToken->z, &iValue)==0 ){
      nExtra = pToken->n+1;
      assert( iValue>=0 );
    }
  }
  pNew = sqlite3DbMallocRawNN(db, sizeof(Expr)+nExtra);
  if( pNew ){
    memset(pNew, 0, sizeof(Expr));
    pNew->op = (u8)op;
    pNew->iAgg = -1;
    if( pToken ){
      if( nExtra==0 ){
        pNew->flags |= EP_IntValue|EP_Leaf;
        pNew->u.iValue = iValue;
      }else{
        pNew->u.zToken = (char*)&pNew[1];
        assert( pToken->z!=0 || pToken->n==0 );
        if( pToken->n ) memcpy(pNew->u.zToken, pToken->z, pToken->n);
        pNew->u.zToken[pToken->n] = 0;
        if( dequote && sqlite3Isquote(pNew->u.zToken[0]) ){
          if( pNew->u.zToken[0]=='"' ) pNew->flags |= EP_DblQuoted;
          sqlite3Dequote(pNew->u.zToken);
        }
      }
    }
#if SQLITE_MAX_EXPR_DEPTH>0
    pNew->nHeight = 1;
#endif  
  }
  return pNew;
}

/*
** Allocate a new expression node from a zero-terminated token that has
** already been dequoted.
*/
Expr *sqlite3Expr(
  sqlite3 *db,            /* Handle for sqlite3DbMallocZero() (may be null) */
  int op,                 /* Expression opcode */
  const char *zToken      /* Token argument.  Might be NULL */
){
  Token x;
  x.z = zToken;
  x.n = zToken ? sqlite3Strlen30(zToken) : 0;
  return sqlite3ExprAlloc(db, op, &x, 0);
}

/*
** Attach subtrees pLeft and pRight to the Expr node pRoot.
**
** If pRoot==NULL that means that a memory allocation error has occurred.
** In that case, delete the subtrees pLeft and pRight.
*/
void sqlite3ExprAttachSubtrees(
  sqlite3 *db,
  Expr *pRoot,
  Expr *pLeft,
  Expr *pRight
){
  if( pRoot==0 ){
    assert( db->mallocFailed );
    sqlite3ExprDelete(db, pLeft);
    sqlite3ExprDelete(db, pRight);
  }else{
    if( pRight ){
      pRoot->pRight = pRight;
      pRoot->flags |= EP_Propagate & pRight->flags;
    }
    if( pLeft ){
      pRoot->pLeft = pLeft;
      pRoot->flags |= EP_Propagate & pLeft->flags;
    }
    exprSetHeight(pRoot);
  }
}

/*
** Allocate an Expr node which joins as many as two subtrees.
**
** One or both of the subtrees can be NULL.  Return a pointer to the new
** Expr node.  Or, if an OOM error occurs, set pParse->db->mallocFailed,
** free the subtrees and return NULL.
*/
Expr *sqlite3PExpr(
  Parse *pParse,          /* Parsing context */
  int op,                 /* Expression opcode */
  Expr *pLeft,            /* Left operand */
  Expr *pRight            /* Right operand */
){
  Expr *p;
  if( op==TK_AND && pParse->nErr==0 ){
    /* Take advantage of short-circuit false optimization for AND */
    p = sqlite3ExprAnd(pParse->db, pLeft, pRight);
  }else{
    p = sqlite3DbMallocRawNN(pParse->db, sizeof(Expr));
    if( p ){
      memset(p, 0, sizeof(Expr));
      p->op = op & TKFLG_MASK;
      p->iAgg = -1;
    }
    sqlite3ExprAttachSubtrees(pParse->db, p, pLeft, pRight);
  }
  if( p ) {
    sqlite3ExprCheckHeight(pParse, p->nHeight);
  }
  return p;
}

/*
** Add pSelect to the Expr.x.pSelect field.  Or, if pExpr is NULL (due
** do a memory allocation failure) then delete the pSelect object.
*/
void sqlite3PExprAddSelect(Parse *pParse, Expr *pExpr, Select *pSelect){
  if( pExpr ){
    pExpr->x.pSelect = pSelect;
    ExprSetProperty(pExpr, EP_xIsSelect|EP_Subquery);
    sqlite3ExprSetHeightAndFlags(pParse, pExpr);
  }else{
    assert( pParse->db->mallocFailed );
    sqlite3SelectDelete(pParse->db, pSelect);
  }
}


/*
** If the expression is always either TRUE or FALSE (respectively),
** then return 1.  If one cannot determine the truth value of the
** expression at compile-time return 0.
**
** This is an optimization.  If is OK to return 0 here even if
** the expression really is always false or false (a false negative).
** But it is a bug to return 1 if the expression might have different
** boolean values in different circumstances (a false positive.)
**
** Note that if the expression is part of conditional for a
** LEFT JOIN, then we cannot determine at compile-time whether or not
** is it true or false, so always return 0.
*/
static int exprAlwaysTrue(Expr *p){
  int v = 0;
  if( ExprHasProperty(p, EP_FromJoin) ) return 0;
  if( !sqlite3ExprIsInteger(p, &v) ) return 0;
  return v!=0;
}
static int exprAlwaysFalse(Expr *p){
  int v = 0;
  if( ExprHasProperty(p, EP_FromJoin) ) return 0;
  if( !sqlite3ExprIsInteger(p, &v) ) return 0;
  return v==0;
}

/*
** Join two expressions using an AND operator.  If either expression is
** NULL, then just return the other expression.
**
** If one side or the other of the AND is known to be false, then instead
** of returning an AND expression, just return a constant expression with
** a value of false.
*/
Expr *sqlite3ExprAnd(sqlite3 *db, Expr *pLeft, Expr *pRight){
  if( pLeft==0 ){
    return pRight;
  }else if( pRight==0 ){
    return pLeft;
  }else if( exprAlwaysFalse(pLeft) || exprAlwaysFalse(pRight) ){
    sqlite3ExprDelete(db, pLeft);
    sqlite3ExprDelete(db, pRight);
    return sqlite3ExprAlloc(db, TK_INTEGER, &sqlite3IntTokens[0], 0);
  }else{
    Expr *pNew = sqlite3ExprAlloc(db, TK_AND, 0, 0);
    sqlite3ExprAttachSubtrees(db, pNew, pLeft, pRight);
    return pNew;
  }
}

/*
** Construct a new expression node for a function with multiple
** arguments.
*/
Expr *sqlite3ExprFunction(Parse *pParse, ExprList *pList, Token *pToken){
  Expr *pNew;
  sqlite3 *db = pParse->db;
  assert( pToken );
  pNew = sqlite3ExprAlloc(db, TK_FUNCTION, pToken, 1);
  if( pNew==0 ){
    sqlite3ExprListDelete(db, pList); /* Avoid memory leak when malloc fails */
    return 0;
  }
  pNew->x.pList = pList;
  assert( !ExprHasProperty(pNew, EP_xIsSelect) );
  sqlite3ExprSetHeightAndFlags(pParse, pNew);
  return pNew;
}

/*
** Assign a variable number to an expression that encodes a wildcard
** in the original SQL statement.  
**
** Wildcards consisting of a single "?" are assigned the next sequential
** variable number.
**
** Wildcards of the form "?nnn" are assigned the number "nnn".  We make
** sure "nnn" is not too big to avoid a denial of service attack when
** the SQL statement comes from an external source.
**
** Wildcards of the form ":aaa", "@aaa", or "$aaa" are assigned the same number
** as the previous instance of the same wildcard.  Or if this is the first
** instance of the wildcard, the next sequential variable number is
** assigned.
*/
void sqlite3ExprAssignVarNumber(Parse *pParse, Expr *pExpr, u32 n){
  sqlite3 *db = pParse->db;
  const char *z;
  ynVar x;

  if( pExpr==0 ) return;
  assert( !ExprHasProperty(pExpr, EP_IntValue|EP_Reduced|EP_TokenOnly) );
  z = pExpr->u.zToken;
  assert( z!=0 );
  assert( z[0]!=0 );
  assert( n==(u32)sqlite3Strlen30(z) );
  if( z[1]==0 ){
    /* Wildcard of the form "?".  Assign the next variable number */
    assert( z[0]=='?' );
    x = (ynVar)(++pParse->nVar);
  }else{
    int doAdd = 0;
    if( z[0]=='?' ){
      /* Wildcard of the form "?nnn".  Convert "nnn" to an integer and
      ** use it as the variable number */
      i64 i;
      int bOk;
      if( n==2 ){ /*OPTIMIZATION-IF-TRUE*/
        i = z[1]-'0';  /* The common case of ?N for a single digit N */
        bOk = 1;
      }else{
        bOk = 0==sqlite3Atoi64(&z[1], &i, n-1, SQLITE_UTF8);
      }
      testcase( i==0 );
      testcase( i==1 );
      testcase( i==db->aLimit[SQLITE_LIMIT_VARIABLE_NUMBER]-1 );
      testcase( i==db->aLimit[SQLITE_LIMIT_VARIABLE_NUMBER] );
      if( bOk==0 || i<1 || i>db->aLimit[SQLITE_LIMIT_VARIABLE_NUMBER] ){
        sqlite3ErrorMsg(pParse, "variable number must be between ?1 and ?%d",
            db->aLimit[SQLITE_LIMIT_VARIABLE_NUMBER]);
        return;
      }
      x = (ynVar)i;
      if( x>pParse->nVar ){
        pParse->nVar = (int)x;
        doAdd = 1;
      }else if( sqlite3VListNumToName(pParse->pVList, x)==0 ){
        doAdd = 1;
      }
    }else{
      /* Wildcards like ":aaa", "$aaa" or "@aaa".  Reuse the same variable
      ** number as the prior appearance of the same name, or if the name
      ** has never appeared before, reuse the same variable number
      */
      x = (ynVar)sqlite3VListNameToNum(pParse->pVList, z, n);
      if( x==0 ){
        x = (ynVar)(++pParse->nVar);
        doAdd = 1;
      }
    }
    if( doAdd ){
      pParse->pVList = sqlite3VListAdd(db, pParse->pVList, z, n, x);
    }
  }
  pExpr->iColumn = x;
  if( x>db->aLimit[SQLITE_LIMIT_VARIABLE_NUMBER] ){
    sqlite3ErrorMsg(pParse, "too many SQL variables");
  }
}

/*
** Recursively delete an expression tree.
*/
static SQLITE_NOINLINE void sqlite3ExprDeleteNN(sqlite3 *db, Expr *p){
  assert( p!=0 );
  /* Sanity check: Assert that the IntValue is non-negative if it exists */
  assert( !ExprHasProperty(p, EP_IntValue) || p->u.iValue>=0 );
#ifdef SQLITE_DEBUG
  if( ExprHasProperty(p, EP_Leaf) && !ExprHasProperty(p, EP_TokenOnly) ){
    assert( p->pLeft==0 );
    assert( p->pRight==0 );
    assert( p->x.pSelect==0 );
  }
#endif
  if( !ExprHasProperty(p, (EP_TokenOnly|EP_Leaf)) ){
    /* The Expr.x union is never used at the same time as Expr.pRight */
    assert( p->x.pList==0 || p->pRight==0 );
    if( p->pLeft && p->op!=TK_SELECT_COLUMN ) sqlite3ExprDeleteNN(db, p->pLeft);
    if( p->pRight ){
      sqlite3ExprDeleteNN(db, p->pRight);
    }else if( ExprHasProperty(p, EP_xIsSelect) ){
      sqlite3SelectDelete(db, p->x.pSelect);
    }else{
      sqlite3ExprListDelete(db, p->x.pList);
    }
  }
  if( ExprHasProperty(p, EP_MemToken) ) sqlite3DbFree(db, p->u.zToken);
  if( !ExprHasProperty(p, EP_Static) ){
    sqlite3DbFreeNN(db, p);
  }
}
void sqlite3ExprDelete(sqlite3 *db, Expr *p){
  if( p ) sqlite3ExprDeleteNN(db, p);
}

/*
** Return the number of bytes allocated for the expression structure 
** passed as the first argument. This is always one of EXPR_FULLSIZE,
** EXPR_REDUCEDSIZE or EXPR_TOKENONLYSIZE.
*/
static int exprStructSize(Expr *p){
  if( ExprHasProperty(p, EP_TokenOnly) ) return EXPR_TOKENONLYSIZE;
  if( ExprHasProperty(p, EP_Reduced) ) return EXPR_REDUCEDSIZE;
  return EXPR_FULLSIZE;
}

/*
** The dupedExpr*Size() routines each return the number of bytes required
** to store a copy of an expression or expression tree.  They differ in
** how much of the tree is measured.
**
**     dupedExprStructSize()     Size of only the Expr structure 
**     dupedExprNodeSize()       Size of Expr + space for token
**     dupedExprSize()           Expr + token + subtree components
**
***************************************************************************
**
** The dupedExprStructSize() function returns two values OR-ed together:  
** (1) the space required for a copy of the Expr structure only and 
** (2) the EP_xxx flags that indicate what the structure size should be.
** The return values is always one of:
**
**      EXPR_FULLSIZE
**      EXPR_REDUCEDSIZE   | EP_Reduced
**      EXPR_TOKENONLYSIZE | EP_TokenOnly
**
** The size of the structure can be found by masking the return value
** of this routine with 0xfff.  The flags can be found by masking the
** return value with EP_Reduced|EP_TokenOnly.
**
** Note that with flags==EXPRDUP_REDUCE, this routines works on full-size
** (unreduced) Expr objects as they or originally constructed by the parser.
** During expression analysis, extra information is computed and moved into
** later parts of teh Expr object and that extra information might get chopped
** off if the expression is reduced.  Note also that it does not work to
** make an EXPRDUP_REDUCE copy of a reduced expression.  It is only legal
** to reduce a pristine expression tree from the parser.  The implementation
** of dupedExprStructSize() contain multiple assert() statements that attempt
** to enforce this constraint.
*/
static int dupedExprStructSize(Expr *p, int flags){
  int nSize;
  assert( flags==EXPRDUP_REDUCE || flags==0 ); /* Only one flag value allowed */
  assert( EXPR_FULLSIZE<=0xfff );
  assert( (0xfff & (EP_Reduced|EP_TokenOnly))==0 );
  if( 0==flags || p->op==TK_SELECT_COLUMN ){
    nSize = EXPR_FULLSIZE;
  }else{
    assert( !ExprHasProperty(p, EP_TokenOnly|EP_Reduced) );
    assert( !ExprHasProperty(p, EP_FromJoin) ); 
    assert( !ExprHasProperty(p, EP_MemToken) );
    assert( !ExprHasProperty(p, EP_NoReduce) );
    if( p->pLeft || p->x.pList ){
      nSize = EXPR_REDUCEDSIZE | EP_Reduced;
    }else{
      assert( p->pRight==0 );
      nSize = EXPR_TOKENONLYSIZE | EP_TokenOnly;
    }
  }
  return nSize;
}

/*
** This function returns the space in bytes required to store the copy 
** of the Expr structure and a copy of the Expr.u.zToken string (if that
** string is defined.)
*/
static int dupedExprNodeSize(Expr *p, int flags){
  int nByte = dupedExprStructSize(p, flags) & 0xfff;
  if( !ExprHasProperty(p, EP_IntValue) && p->u.zToken ){
    nByte += sqlite3Strlen30(p->u.zToken)+1;
  }
  return ROUND8(nByte);
}

/*
** Return the number of bytes required to create a duplicate of the 
** expression passed as the first argument. The second argument is a
** mask containing EXPRDUP_XXX flags.
**
** The value returned includes space to create a copy of the Expr struct
** itself and the buffer referred to by Expr.u.zToken, if any.
**
** If the EXPRDUP_REDUCE flag is set, then the return value includes 
** space to duplicate all Expr nodes in the tree formed by Expr.pLeft 
** and Expr.pRight variables (but not for any structures pointed to or 
** descended from the Expr.x.pList or Expr.x.pSelect variables).
*/
static int dupedExprSize(Expr *p, int flags){
  int nByte = 0;
  if( p ){
    nByte = dupedExprNodeSize(p, flags);
    if( flags&EXPRDUP_REDUCE ){
      nByte += dupedExprSize(p->pLeft, flags) + dupedExprSize(p->pRight, flags);
    }
  }
  return nByte;
}

/*
** This function is similar to sqlite3ExprDup(), except that if pzBuffer 
** is not NULL then *pzBuffer is assumed to point to a buffer large enough 
** to store the copy of expression p, the copies of p->u.zToken
** (if applicable), and the copies of the p->pLeft and p->pRight expressions,
** if any. Before returning, *pzBuffer is set to the first byte past the
** portion of the buffer copied into by this function.
*/
static Expr *exprDup(sqlite3 *db, Expr *p, int dupFlags, u8 **pzBuffer){
  Expr *pNew;           /* Value to return */
  u8 *zAlloc;           /* Memory space from which to build Expr object */
  u32 staticFlag;       /* EP_Static if space not obtained from malloc */

  assert( db!=0 );
  assert( p );
  assert( dupFlags==0 || dupFlags==EXPRDUP_REDUCE );
  assert( pzBuffer==0 || dupFlags==EXPRDUP_REDUCE );

  /* Figure out where to write the new Expr structure. */
  if( pzBuffer ){
    zAlloc = *pzBuffer;
    staticFlag = EP_Static;
  }else{
    zAlloc = sqlite3DbMallocRawNN(db, dupedExprSize(p, dupFlags));
    staticFlag = 0;
  }
  pNew = (Expr *)zAlloc;

  if( pNew ){
    /* Set nNewSize to the size allocated for the structure pointed to
    ** by pNew. This is either EXPR_FULLSIZE, EXPR_REDUCEDSIZE or
    ** EXPR_TOKENONLYSIZE. nToken is set to the number of bytes consumed
    ** by the copy of the p->u.zToken string (if any).
    */
    const unsigned nStructSize = dupedExprStructSize(p, dupFlags);
    const int nNewSize = nStructSize & 0xfff;
    int nToken;
    if( !ExprHasProperty(p, EP_IntValue) && p->u.zToken ){
      nToken = sqlite3Strlen30(p->u.zToken) + 1;
    }else{
      nToken = 0;
    }
    if( dupFlags ){
      assert( ExprHasProperty(p, EP_Reduced)==0 );
      memcpy(zAlloc, p, nNewSize);
    }else{
      u32 nSize = (u32)exprStructSize(p);
      memcpy(zAlloc, p, nSize);
      if( nSize<EXPR_FULLSIZE ){ 
        memset(&zAlloc[nSize], 0, EXPR_FULLSIZE-nSize);
      }
    }

    /* Set the EP_Reduced, EP_TokenOnly, and EP_Static flags appropriately. */
    pNew->flags &= ~(EP_Reduced|EP_TokenOnly|EP_Static|EP_MemToken);
    pNew->flags |= nStructSize & (EP_Reduced|EP_TokenOnly);
    pNew->flags |= staticFlag;

    /* Copy the p->u.zToken string, if any. */
    if( nToken ){
      char *zToken = pNew->u.zToken = (char*)&zAlloc[nNewSize];
      memcpy(zToken, p->u.zToken, nToken);
    }

    if( 0==((p->flags|pNew->flags) & (EP_TokenOnly|EP_Leaf)) ){
      /* Fill in the pNew->x.pSelect or pNew->x.pList member. */
      if( ExprHasProperty(p, EP_xIsSelect) ){
        pNew->x.pSelect = sqlite3SelectDup(db, p->x.pSelect, dupFlags);
      }else{
        pNew->x.pList = sqlite3ExprListDup(db, p->x.pList, dupFlags);
      }
    }

    /* Fill in pNew->pLeft and pNew->pRight. */
    if( ExprHasProperty(pNew, EP_Reduced|EP_TokenOnly) ){
      zAlloc += dupedExprNodeSize(p, dupFlags);
      if( !ExprHasProperty(pNew, EP_TokenOnly|EP_Leaf) ){
        pNew->pLeft = p->pLeft ?
                      exprDup(db, p->pLeft, EXPRDUP_REDUCE, &zAlloc) : 0;
        pNew->pRight = p->pRight ?
                       exprDup(db, p->pRight, EXPRDUP_REDUCE, &zAlloc) : 0;
      }
      if( pzBuffer ){
        *pzBuffer = zAlloc;
      }
    }else{
      if( !ExprHasProperty(p, EP_TokenOnly|EP_Leaf) ){
        if( pNew->op==TK_SELECT_COLUMN ){
          pNew->pLeft = p->pLeft;
          assert( p->iColumn==0 || p->pRight==0 );
          assert( p->pRight==0  || p->pRight==p->pLeft );
        }else{
          pNew->pLeft = sqlite3ExprDup(db, p->pLeft, 0);
        }
        pNew->pRight = sqlite3ExprDup(db, p->pRight, 0);
      }
    }
  }
  return pNew;
}

/*
** Create and return a deep copy of the object passed as the second 
** argument. If an OOM condition is encountered, NULL is returned
** and the db->mallocFailed flag set.
*/
#ifndef SQLITE_OMIT_CTE
static With *withDup(sqlite3 *db, With *p){
  With *pRet = 0;
  if( p ){
    int nByte = sizeof(*p) + sizeof(p->a[0]) * (p->nCte-1);
    pRet = sqlite3DbMallocZero(db, nByte);
    if( pRet ){
      int i;
      pRet->nCte = p->nCte;
      for(i=0; i<p->nCte; i++){
        pRet->a[i].pSelect = sqlite3SelectDup(db, p->a[i].pSelect, 0);
        pRet->a[i].pCols = sqlite3ExprListDup(db, p->a[i].pCols, 0);
        pRet->a[i].zName = sqlite3DbStrDup(db, p->a[i].zName);
      }
    }
  }
  return pRet;
}
#else
# define withDup(x,y) 0
#endif

/*
** The following group of routines make deep copies of expressions,
** expression lists, ID lists, and select statements.  The copies can
** be deleted (by being passed to their respective ...Delete() routines)
** without effecting the originals.
**
** The expression list, ID, and source lists return by sqlite3ExprListDup(),
** sqlite3IdListDup(), and sqlite3SrcListDup() can not be further expanded 
** by subsequent calls to sqlite*ListAppend() routines.
**
** Any tables that the SrcList might point to are not duplicated.
**
** The flags parameter contains a combination of the EXPRDUP_XXX flags.
** If the EXPRDUP_REDUCE flag is set, then the structure returned is a
** truncated version of the usual Expr structure that will be stored as
** part of the in-memory representation of the database schema.
*/
Expr *sqlite3ExprDup(sqlite3 *db, Expr *p, int flags){
  assert( flags==0 || flags==EXPRDUP_REDUCE );
  return p ? exprDup(db, p, flags, 0) : 0;
}
ExprList *sqlite3ExprListDup(sqlite3 *db, ExprList *p, int flags){
  ExprList *pNew;
  struct ExprList_item *pItem, *pOldItem;
  int i;
  Expr *pPriorSelectCol = 0;
  assert( db!=0 );
  if( p==0 ) return 0;
  pNew = sqlite3DbMallocRawNN(db, 
             sizeof(*pNew)+sizeof(pNew->a[0])*(p->nExpr-1) );
  if( pNew==0 ) return 0;
  pNew->nAlloc = pNew->nExpr = p->nExpr;
  pItem = pNew->a;
  pOldItem = p->a;
  for(i=0; i<p->nExpr; i++, pItem++, pOldItem++){
    Expr *pOldExpr = pOldItem->pExpr;
    Expr *pNewExpr;
    pItem->pExpr = sqlite3ExprDup(db, pOldExpr, flags);
    if( pOldExpr 
     && pOldExpr->op==TK_SELECT_COLUMN
     && (pNewExpr = pItem->pExpr)!=0 
    ){
      assert( pNewExpr->iColumn==0 || i>0 );
      if( pNewExpr->iColumn==0 ){
        assert( pOldExpr->pLeft==pOldExpr->pRight );
        pPriorSelectCol = pNewExpr->pLeft = pNewExpr->pRight;
      }else{
        assert( i>0 );
        assert( pItem[-1].pExpr!=0 );
        assert( pNewExpr->iColumn==pItem[-1].pExpr->iColumn+1 );
        assert( pPriorSelectCol==pItem[-1].pExpr->pLeft );
        pNewExpr->pLeft = pPriorSelectCol;
      }
    }
    pItem->zName = sqlite3DbStrDup(db, pOldItem->zName);
    pItem->zSpan = sqlite3DbStrDup(db, pOldItem->zSpan);
    pItem->sortOrder = pOldItem->sortOrder;
    pItem->done = 0;
    pItem->bSpanIsTab = pOldItem->bSpanIsTab;
    pItem->u = pOldItem->u;
  }
  return pNew;
}

/*
** If cursors, triggers, views and subqueries are all omitted from
** the build, then none of the following routines, except for 
** sqlite3SelectDup(), can be called. sqlite3SelectDup() is sometimes
** called with a NULL argument.
*/
#if !defined(SQLITE_OMIT_VIEW) || !defined(SQLITE_OMIT_TRIGGER) \
 || !defined(SQLITE_OMIT_SUBQUERY)
SrcList *sqlite3SrcListDup(sqlite3 *db, SrcList *p, int flags){
  SrcList *pNew;
  int i;
  int nByte;
  assert( db!=0 );
  if( p==0 ) return 0;
  nByte = sizeof(*p) + (p->nSrc>0 ? sizeof(p->a[0]) * (p->nSrc-1) : 0);
  pNew = sqlite3DbMallocRawNN(db, nByte );
  if( pNew==0 ) return 0;
  pNew->nSrc = pNew->nAlloc = p->nSrc;
  for(i=0; i<p->nSrc; i++){
    struct SrcList_item *pNewItem = &pNew->a[i];
    struct SrcList_item *pOldItem = &p->a[i];
    Table *pTab;
    pNewItem->pSchema = pOldItem->pSchema;
    pNewItem->zDatabase = sqlite3DbStrDup(db, pOldItem->zDatabase);
    pNewItem->zName = sqlite3DbStrDup(db, pOldItem->zName);
    pNewItem->zAlias = sqlite3DbStrDup(db, pOldItem->zAlias);
    pNewItem->fg = pOldItem->fg;
    pNewItem->iCursor = pOldItem->iCursor;
    pNewItem->addrFillSub = pOldItem->addrFillSub;
    pNewItem->regReturn = pOldItem->regReturn;
    if( pNewItem->fg.isIndexedBy ){
      pNewItem->u1.zIndexedBy = sqlite3DbStrDup(db, pOldItem->u1.zIndexedBy);
    }
    pNewItem->pIBIndex = pOldItem->pIBIndex;
    if( pNewItem->fg.isTabFunc ){
      pNewItem->u1.pFuncArg = 
          sqlite3ExprListDup(db, pOldItem->u1.pFuncArg, flags);
    }
    pTab = pNewItem->pTab = pOldItem->pTab;
    if( pTab ){
      pTab->nTabRef++;
    }
    pNewItem->pSelect = sqlite3SelectDup(db, pOldItem->pSelect, flags);
    pNewItem->pOn = sqlite3ExprDup(db, pOldItem->pOn, flags);
    pNewItem->pUsing = sqlite3IdListDup(db, pOldItem->pUsing);
    pNewItem->colUsed = pOldItem->colUsed;
  }
  return pNew;
}
IdList *sqlite3IdListDup(sqlite3 *db, IdList *p){
  IdList *pNew;
  int i;
  assert( db!=0 );
  if( p==0 ) return 0;
  pNew = sqlite3DbMallocRawNN(db, sizeof(*pNew) );
  if( pNew==0 ) return 0;
  pNew->nId = p->nId;
  pNew->a = sqlite3DbMallocRawNN(db, p->nId*sizeof(p->a[0]) );
  if( pNew->a==0 ){
    sqlite3DbFreeNN(db, pNew);
    return 0;
  }
  /* Note that because the size of the allocation for p->a[] is not
  ** necessarily a power of two, sqlite3IdListAppend() may not be called
  ** on the duplicate created by this function. */
  for(i=0; i<p->nId; i++){
    struct IdList_item *pNewItem = &pNew->a[i];
    struct IdList_item *pOldItem = &p->a[i];
    pNewItem->zName = sqlite3DbStrDup(db, pOldItem->zName);
    pNewItem->idx = pOldItem->idx;
  }
  return pNew;
}
Select *sqlite3SelectDup(sqlite3 *db, Select *pDup, int flags){
  Select *pRet = 0;
  Select *pNext = 0;
  Select **pp = &pRet;
  Select *p;

  assert( db!=0 );
  for(p=pDup; p; p=p->pPrior){
    Select *pNew = sqlite3DbMallocRawNN(db, sizeof(*p) );
    if( pNew==0 ) break;
    pNew->pEList = sqlite3ExprListDup(db, p->pEList, flags);
    pNew->pSrc = sqlite3SrcListDup(db, p->pSrc, flags);
    pNew->pWhere = sqlite3ExprDup(db, p->pWhere, flags);
    pNew->pGroupBy = sqlite3ExprListDup(db, p->pGroupBy, flags);
    pNew->pHaving = sqlite3ExprDup(db, p->pHaving, flags);
    pNew->pOrderBy = sqlite3ExprListDup(db, p->pOrderBy, flags);
    pNew->op = p->op;
    pNew->pNext = pNext;
    pNew->pPrior = 0;
    pNew->pLimit = sqlite3ExprDup(db, p->pLimit, flags);
    pNew->pOffset = sqlite3ExprDup(db, p->pOffset, flags);
    pNew->iLimit = 0;
    pNew->iOffset = 0;
    pNew->selFlags = p->selFlags & ~SF_UsesEphemeral;
    pNew->addrOpenEphm[0] = -1;
    pNew->addrOpenEphm[1] = -1;
    pNew->nSelectRow = p->nSelectRow;
    pNew->pWith = withDup(db, p->pWith);
    sqlite3SelectSetName(pNew, p->zSelName);
    *pp = pNew;
    pp = &pNew->pPrior;
    pNext = pNew;
  }

  return pRet;
}
#else
Select *sqlite3SelectDup(sqlite3 *db, Select *p, int flags){
  assert( p==0 );
  return 0;
}
#endif


/*
** Add a new element to the end of an expression list.  If pList is
** initially NULL, then create a new expression list.
**
** If a memory allocation error occurs, the entire list is freed and
** NULL is returned.  If non-NULL is returned, then it is guaranteed
** that the new entry was successfully appended.
*/
ExprList *sqlite3ExprListAppend(
  Parse *pParse,          /* Parsing context */
  ExprList *pList,        /* List to which to append. Might be NULL */
  Expr *pExpr             /* Expression to be appended. Might be NULL */
){
  struct ExprList_item *pItem;
  sqlite3 *db = pParse->db;
  assert( db!=0 );
  if( pList==0 ){
    pList = sqlite3DbMallocRawNN(db, sizeof(ExprList) );
    if( pList==0 ){
      goto no_mem;
    }
    pList->nExpr = 0;
    pList->nAlloc = 1;
  }else if( pList->nExpr==pList->nAlloc ){
    ExprList *pNew;
    pNew = sqlite3DbRealloc(db, pList, 
             sizeof(*pList)+(2*pList->nAlloc - 1)*sizeof(pList->a[0]));
    if( pNew==0 ){
      goto no_mem;
    }
    pList = pNew;
    pList->nAlloc *= 2;
  }
  pItem = &pList->a[pList->nExpr++];
  assert( offsetof(struct ExprList_item,zName)==sizeof(pItem->pExpr) );
  assert( offsetof(struct ExprList_item,pExpr)==0 );
  memset(&pItem->zName,0,sizeof(*pItem)-offsetof(struct ExprList_item,zName));
  pItem->pExpr = pExpr;
  return pList;

no_mem:     
  /* Avoid leaking memory if malloc has failed. */
  sqlite3ExprDelete(db, pExpr);
  sqlite3ExprListDelete(db, pList);
  return 0;
}

/*
** pColumns and pExpr form a vector assignment which is part of the SET
** clause of an UPDATE statement.  Like this:
**
**        (a,b,c) = (expr1,expr2,expr3)
** Or:    (a,b,c) = (SELECT x,y,z FROM ....)
**
** For each term of the vector assignment, append new entries to the
** expression list pList.  In the case of a subquery on the RHS, append
** TK_SELECT_COLUMN expressions.
*/
ExprList *sqlite3ExprListAppendVector(
  Parse *pParse,         /* Parsing context */
  ExprList *pList,       /* List to which to append. Might be NULL */
  IdList *pColumns,      /* List of names of LHS of the assignment */
  Expr *pExpr            /* Vector expression to be appended. Might be NULL */
){
  sqlite3 *db = pParse->db;
  int n;
  int i;
  int iFirst = pList ? pList->nExpr : 0;
  /* pColumns can only be NULL due to an OOM but an OOM will cause an
  ** exit prior to this routine being invoked */
  if( NEVER(pColumns==0) ) goto vector_append_error;
  if( pExpr==0 ) goto vector_append_error;

  /* If the RHS is a vector, then we can immediately check to see that 
  ** the size of the RHS and LHS match.  But if the RHS is a SELECT, 
  ** wildcards ("*") in the result set of the SELECT must be expanded before
  ** we can do the size check, so defer the size check until code generation.
  */
  if( pExpr->op!=TK_SELECT && pColumns->nId!=(n=sqlite3ExprVectorSize(pExpr)) ){
    sqlite3ErrorMsg(pParse, "%d columns assigned %d values",
                    pColumns->nId, n);
    goto vector_append_error;
  }

  for(i=0; i<pColumns->nId; i++){
    Expr *pSubExpr = sqlite3ExprForVectorField(pParse, pExpr, i);
    pList = sqlite3ExprListAppend(pParse, pList, pSubExpr);
    if( pList ){
      assert( pList->nExpr==iFirst+i+1 );
      pList->a[pList->nExpr-1].zName = pColumns->a[i].zName;
      pColumns->a[i].zName = 0;
    }
  }

  if( !db->mallocFailed && pExpr->op==TK_SELECT && ALWAYS(pList!=0) ){
    Expr *pFirst = pList->a[iFirst].pExpr;
    assert( pFirst!=0 );
    assert( pFirst->op==TK_SELECT_COLUMN );
     
    /* Store the SELECT statement in pRight so it will be deleted when
    ** sqlite3ExprListDelete() is called */
    pFirst->pRight = pExpr;
    pExpr = 0;

    /* Remember the size of the LHS in iTable so that we can check that
    ** the RHS and LHS sizes match during code generation. */
    pFirst->iTable = pColumns->nId;
  }

vector_append_error:
  sqlite3ExprDelete(db, pExpr);
  sqlite3IdListDelete(db, pColumns);
  return pList;
}

/*
** Set the sort order for the last element on the given ExprList.
*/
void sqlite3ExprListSetSortOrder(ExprList *p, int iSortOrder){
  if( p==0 ) return;
  assert( SQLITE_SO_UNDEFINED<0 && SQLITE_SO_ASC>=0 && SQLITE_SO_DESC>0 );
  assert( p->nExpr>0 );
  if( iSortOrder<0 ){
    assert( p->a[p->nExpr-1].sortOrder==SQLITE_SO_ASC );
    return;
  }
  p->a[p->nExpr-1].sortOrder = (u8)iSortOrder;
}

/*
** Set the ExprList.a[].zName element of the most recently added item
** on the expression list.
**
** pList might be NULL following an OOM error.  But pName should never be
** NULL.  If a memory allocation fails, the pParse->db->mallocFailed flag
** is set.
*/
void sqlite3ExprListSetName(
  Parse *pParse,          /* Parsing context */
  ExprList *pList,        /* List to which to add the span. */
  Token *pName,           /* Name to be added */
  int dequote             /* True to cause the name to be dequoted */
){
  assert( pList!=0 || pParse->db->mallocFailed!=0 );
  if( pList ){
    struct ExprList_item *pItem;
    assert( pList->nExpr>0 );
    pItem = &pList->a[pList->nExpr-1];
    assert( pItem->zName==0 );
    pItem->zName = sqlite3DbStrNDup(pParse->db, pName->z, pName->n);
    if( dequote ) sqlite3Dequote(pItem->zName);
  }
}

/*
** Set the ExprList.a[].zSpan element of the most recently added item
** on the expression list.
**
** pList might be NULL following an OOM error.  But pSpan should never be
** NULL.  If a memory allocation fails, the pParse->db->mallocFailed flag
** is set.
*/
void sqlite3ExprListSetSpan(
  Parse *pParse,          /* Parsing context */
  ExprList *pList,        /* List to which to add the span. */
  ExprSpan *pSpan         /* The span to be added */
){
  sqlite3 *db = pParse->db;
  assert( pList!=0 || db->mallocFailed!=0 );
  if( pList ){
    struct ExprList_item *pItem = &pList->a[pList->nExpr-1];
    assert( pList->nExpr>0 );
    assert( db->mallocFailed || pItem->pExpr==pSpan->pExpr );
    sqlite3DbFree(db, pItem->zSpan);
    pItem->zSpan = sqlite3DbStrNDup(db, (char*)pSpan->zStart,
                                    (int)(pSpan->zEnd - pSpan->zStart));
  }
}

/*
** If the expression list pEList contains more than iLimit elements,
** leave an error message in pParse.
*/
void sqlite3ExprListCheckLength(
  Parse *pParse,
  ExprList *pEList,
  const char *zObject
){
  int mx = pParse->db->aLimit[SQLITE_LIMIT_COLUMN];
  testcase( pEList && pEList->nExpr==mx );
  testcase( pEList && pEList->nExpr==mx+1 );
  if( pEList && pEList->nExpr>mx ){
    sqlite3ErrorMsg(pParse, "too many columns in %s", zObject);
  }
}

/*
** Delete an entire expression list.
*/
static SQLITE_NOINLINE void exprListDeleteNN(sqlite3 *db, ExprList *pList){
  int i = pList->nExpr;
  struct ExprList_item *pItem =  pList->a;
  assert( pList->nExpr>0 );
  do{
    sqlite3ExprDelete(db, pItem->pExpr);
    sqlite3DbFree(db, pItem->zName);
    sqlite3DbFree(db, pItem->zSpan);
    pItem++;
  }while( --i>0 );
  sqlite3DbFreeNN(db, pList);
}
void sqlite3ExprListDelete(sqlite3 *db, ExprList *pList){
  if( pList ) exprListDeleteNN(db, pList);
}

/*
** Return the bitwise-OR of all Expr.flags fields in the given
** ExprList.
*/
u32 sqlite3ExprListFlags(const ExprList *pList){
  int i;
  u32 m = 0;
  if( pList ){
    for(i=0; i<pList->nExpr; i++){
       Expr *pExpr = pList->a[i].pExpr;
       assert( pExpr!=0 );
       m |= pExpr->flags;
    }
  }
  return m;
}

/*
** These routines are Walker callbacks used to check expressions to
** see if they are "constant" for some definition of constant.  The
** Walker.eCode value determines the type of "constant" we are looking
** for.
**
** These callback routines are used to implement the following:
**
**     sqlite3ExprIsConstant()                  pWalker->eCode==1
**     sqlite3ExprIsConstantNotJoin()           pWalker->eCode==2
**     sqlite3ExprIsTableConstant()             pWalker->eCode==3
**     sqlite3ExprIsConstantOrFunction()        pWalker->eCode==4 or 5
**
** In all cases, the callbacks set Walker.eCode=0 and abort if the expression
** is found to not be a constant.
**
** The sqlite3ExprIsConstantOrFunction() is used for evaluating expressions
** in a CREATE TABLE statement.  The Walker.eCode value is 5 when parsing
** an existing schema and 4 when processing a new statement.  A bound
** parameter raises an error for new statements, but is silently converted
** to NULL for existing schemas.  This allows sqlite_master tables that 
** contain a bound parameter because they were generated by older versions
** of SQLite to be parsed by newer versions of SQLite without raising a
** malformed schema error.
*/
static int exprNodeIsConstant(Walker *pWalker, Expr *pExpr){

  /* If pWalker->eCode is 2 then any term of the expression that comes from
  ** the ON or USING clauses of a left join disqualifies the expression
  ** from being considered constant. */
  if( pWalker->eCode==2 && ExprHasProperty(pExpr, EP_FromJoin) ){
    pWalker->eCode = 0;
    return WRC_Abort;
  }

  switch( pExpr->op ){
    /* Consider functions to be constant if all their arguments are constant
    ** and either pWalker->eCode==4 or 5 or the function has the
    ** SQLITE_FUNC_CONST flag. */
    case TK_FUNCTION:
      if( pWalker->eCode>=4 || ExprHasProperty(pExpr,EP_ConstFunc) ){
        return WRC_Continue;
      }else{
        pWalker->eCode = 0;
        return WRC_Abort;
      }
    case TK_ID:
    case TK_COLUMN:
    case TK_AGG_FUNCTION:
    case TK_AGG_COLUMN:
      testcase( pExpr->op==TK_ID );
      testcase( pExpr->op==TK_COLUMN );
      testcase( pExpr->op==TK_AGG_FUNCTION );
      testcase( pExpr->op==TK_AGG_COLUMN );
      if( pWalker->eCode==3 && pExpr->iTable==pWalker->u.iCur ){
        return WRC_Continue;
      }
      /* Fall through */
    case TK_IF_NULL_ROW:
      testcase( pExpr->op==TK_IF_NULL_ROW );
      pWalker->eCode = 0;
      return WRC_Abort;
    case TK_VARIABLE:
      if( pWalker->eCode==5 ){
        /* Silently convert bound parameters that appear inside of CREATE
        ** statements into a NULL when parsing the CREATE statement text out
        ** of the sqlite_master table */
        pExpr->op = TK_NULL;
      }else if( pWalker->eCode==4 ){
        /* A bound parameter in a CREATE statement that originates from
        ** sqlite3_prepare() causes an error */
        pWalker->eCode = 0;
        return WRC_Abort;
      }
      /* Fall through */
    default:
      testcase( pExpr->op==TK_SELECT ); /* selectNodeIsConstant will disallow */
      testcase( pExpr->op==TK_EXISTS ); /* selectNodeIsConstant will disallow */
      return WRC_Continue;
  }
}
static int selectNodeIsConstant(Walker *pWalker, Select *NotUsed){
  UNUSED_PARAMETER(NotUsed);
  pWalker->eCode = 0;
  return WRC_Abort;
}
static int exprIsConst(Expr *p, int initFlag, int iCur){
  Walker w;
  w.eCode = initFlag;
  w.xExprCallback = exprNodeIsConstant;
  w.xSelectCallback = selectNodeIsConstant;
#ifdef SQLITE_DEBUG
  w.xSelectCallback2 = sqlite3SelectWalkAssert2;
#endif
  w.u.iCur = iCur;
  sqlite3WalkExpr(&w, p);
  return w.eCode;
}

/*
** Walk an expression tree.  Return non-zero if the expression is constant
** and 0 if it involves variables or function calls.
**
** For the purposes of this function, a double-quoted string (ex: "abc")
** is considered a variable but a single-quoted string (ex: 'abc') is
** a constant.
*/
int sqlite3ExprIsConstant(Expr *p){
  return exprIsConst(p, 1, 0);
}

/*
** Walk an expression tree.  Return non-zero if the expression is constant
** that does no originate from the ON or USING clauses of a join.
** Return 0 if it involves variables or function calls or terms from
** an ON or USING clause.
*/
int sqlite3ExprIsConstantNotJoin(Expr *p){
  return exprIsConst(p, 2, 0);
}

/*
** Walk an expression tree.  Return non-zero if the expression is constant
** for any single row of the table with cursor iCur.  In other words, the
** expression must not refer to any non-deterministic function nor any
** table other than iCur.
*/
int sqlite3ExprIsTableConstant(Expr *p, int iCur){
  return exprIsConst(p, 3, iCur);
}


/*
** sqlite3WalkExpr() callback used by sqlite3ExprIsConstantOrGroupBy().
*/
static int exprNodeIsConstantOrGroupBy(Walker *pWalker, Expr *pExpr){
  ExprList *pGroupBy = pWalker->u.pGroupBy;
  int i;

  /* Check if pExpr is identical to any GROUP BY term. If so, consider
  ** it constant.  */
  for(i=0; i<pGroupBy->nExpr; i++){
    Expr *p = pGroupBy->a[i].pExpr;
    if( sqlite3ExprCompare(0, pExpr, p, -1)<2 ){
      CollSeq *pColl = sqlite3ExprCollSeq(pWalker->pParse, p);
      if( pColl==0 || sqlite3_stricmp("BINARY", pColl->zName)==0 ){
        return WRC_Prune;
      }
    }
  }

  /* Check if pExpr is a sub-select. If so, consider it variable. */
  if( ExprHasProperty(pExpr, EP_xIsSelect) ){
    pWalker->eCode = 0;
    return WRC_Abort;
  }

  return exprNodeIsConstant(pWalker, pExpr);
}

/*
** Walk the expression tree passed as the first argument. Return non-zero
** if the expression consists entirely of constants or copies of terms 
** in pGroupBy that sort with the BINARY collation sequence.
**
** This routine is used to determine if a term of the HAVING clause can
** be promoted into the WHERE clause.  In order for such a promotion to work,
** the value of the HAVING clause term must be the same for all members of
** a "group".  The requirement that the GROUP BY term must be BINARY
** assumes that no other collating sequence will have a finer-grained
** grouping than binary.  In other words (A=B COLLATE binary) implies
** A=B in every other collating sequence.  The requirement that the
** GROUP BY be BINARY is stricter than necessary.  It would also work
** to promote HAVING clauses that use the same alternative collating
** sequence as the GROUP BY term, but that is much harder to check,
** alternative collating sequences are uncommon, and this is only an
** optimization, so we take the easy way out and simply require the
** GROUP BY to use the BINARY collating sequence.
*/
int sqlite3ExprIsConstantOrGroupBy(Parse *pParse, Expr *p, ExprList *pGroupBy){
  Walker w;
  w.eCode = 1;
  w.xExprCallback = exprNodeIsConstantOrGroupBy;
  w.xSelectCallback = 0;
  w.u.pGroupBy = pGroupBy;
  w.pParse = pParse;
  sqlite3WalkExpr(&w, p);
  return w.eCode;
}

/*
** Walk an expression tree.  Return non-zero if the expression is constant
** or a function call with constant arguments.  Return and 0 if there
** are any variables.
**
** For the purposes of this function, a double-quoted string (ex: "abc")
** is considered a variable but a single-quoted string (ex: 'abc') is
** a constant.
*/
int sqlite3ExprIsConstantOrFunction(Expr *p, u8 isInit){
  assert( isInit==0 || isInit==1 );
  return exprIsConst(p, 4+isInit, 0);
}

#ifdef SQLITE_ENABLE_CURSOR_HINTS
/*
** Walk an expression tree.  Return 1 if the expression contains a
** subquery of some kind.  Return 0 if there are no subqueries.
*/
int sqlite3ExprContainsSubquery(Expr *p){
  Walker w;
  w.eCode = 1;
  w.xExprCallback = sqlite3ExprWalkNoop;
  w.xSelectCallback = selectNodeIsConstant;
#ifdef SQLITE_DEBUG
  w.xSelectCallback2 = sqlite3SelectWalkAssert2;
#endif
  sqlite3WalkExpr(&w, p);
  return w.eCode==0;
}
#endif

/*
** If the expression p codes a constant integer that is small enough
** to fit in a 32-bit integer, return 1 and put the value of the integer
** in *pValue.  If the expression is not an integer or if it is too big
** to fit in a signed 32-bit integer, return 0 and leave *pValue unchanged.
*/
int sqlite3ExprIsInteger(Expr *p, int *pValue){
  int rc = 0;
  if( p==0 ) return 0;  /* Can only happen following on OOM */

  /* If an expression is an integer literal that fits in a signed 32-bit
  ** integer, then the EP_IntValue flag will have already been set */
  assert( p->op!=TK_INTEGER || (p->flags & EP_IntValue)!=0
           || sqlite3GetInt32(p->u.zToken, &rc)==0 );

  if( p->flags & EP_IntValue ){
    *pValue = p->u.iValue;
    return 1;
  }
  switch( p->op ){
    case TK_UPLUS: {
      rc = sqlite3ExprIsInteger(p->pLeft, pValue);
      break;
    }
    case TK_UMINUS: {
      int v;
      if( sqlite3ExprIsInteger(p->pLeft, &v) ){
        assert( v!=(-2147483647-1) );
        *pValue = -v;
        rc = 1;
      }
      break;
    }
    default: break;
  }
  return rc;
}

/*
** Return FALSE if there is no chance that the expression can be NULL.
**
** If the expression might be NULL or if the expression is too complex
** to tell return TRUE.  
**
** This routine is used as an optimization, to skip OP_IsNull opcodes
** when we know that a value cannot be NULL.  Hence, a false positive
** (returning TRUE when in fact the expression can never be NULL) might
** be a small performance hit but is otherwise harmless.  On the other
** hand, a false negative (returning FALSE when the result could be NULL)
** will likely result in an incorrect answer.  So when in doubt, return
** TRUE.
*/
int sqlite3ExprCanBeNull(const Expr *p){
  u8 op;
  while( p->op==TK_UPLUS || p->op==TK_UMINUS ){ p = p->pLeft; }
  op = p->op;
  if( op==TK_REGISTER ) op = p->op2;
  switch( op ){
    case TK_INTEGER:
    case TK_STRING:
    case TK_FLOAT:
    case TK_BLOB:
      return 0;
    case TK_COLUMN:
      assert( p->pTab!=0 );
      return ExprHasProperty(p, EP_CanBeNull) ||
             (p->iColumn>=0 && p->pTab->aCol[p->iColumn].notNull==0);
    default:
      return 1;
  }
}

/*
** Return TRUE if the given expression is a constant which would be
** unchanged by OP_Affinity with the affinity given in the second
** argument.
**
** This routine is used to determine if the OP_Affinity operation
** can be omitted.  When in doubt return FALSE.  A false negative
** is harmless.  A false positive, however, can result in the wrong
** answer.
*/
int sqlite3ExprNeedsNoAffinityChange(const Expr *p, char aff){
  u8 op;
  if( aff==SQLITE_AFF_BLOB ) return 1;
  while( p->op==TK_UPLUS || p->op==TK_UMINUS ){ p = p->pLeft; }
  op = p->op;
  if( op==TK_REGISTER ) op = p->op2;
  switch( op ){
    case TK_INTEGER: {
      return aff==SQLITE_AFF_INTEGER || aff==SQLITE_AFF_NUMERIC;
    }
    case TK_FLOAT: {
      return aff==SQLITE_AFF_REAL || aff==SQLITE_AFF_NUMERIC;
    }
    case TK_STRING: {
      return aff==SQLITE_AFF_TEXT;
    }
    case TK_BLOB: {
      return 1;
    }
    case TK_COLUMN: {
      assert( p->iTable>=0 );  /* p cannot be part of a CHECK constraint */
      return p->iColumn<0
          && (aff==SQLITE_AFF_INTEGER || aff==SQLITE_AFF_NUMERIC);
    }
    default: {
      return 0;
    }
  }
}

/*
** Return TRUE if the given string is a row-id column name.
*/
int sqlite3IsRowid(const char *z){
  if( sqlite3StrICmp(z, "_ROWID_")==0 ) return 1;
  if( sqlite3StrICmp(z, "ROWID")==0 ) return 1;
  if( sqlite3StrICmp(z, "OID")==0 ) return 1;
  return 0;
}

/*
** pX is the RHS of an IN operator.  If pX is a SELECT statement 
** that can be simplified to a direct table access, then return
** a pointer to the SELECT statement.  If pX is not a SELECT statement,
** or if the SELECT statement needs to be manifested into a transient
** table, then return NULL.
*/
#ifndef SQLITE_OMIT_SUBQUERY
static Select *isCandidateForInOpt(Expr *pX){
  Select *p;
  SrcList *pSrc;
  ExprList *pEList;
  Table *pTab;
  int i;
  if( !ExprHasProperty(pX, EP_xIsSelect) ) return 0;  /* Not a subquery */
  if( ExprHasProperty(pX, EP_VarSelect)  ) return 0;  /* Correlated subq */
  p = pX->x.pSelect;
  if( p->pPrior ) return 0;              /* Not a compound SELECT */
  if( p->selFlags & (SF_Distinct|SF_Aggregate) ){
    testcase( (p->selFlags & (SF_Distinct|SF_Aggregate))==SF_Distinct );
    testcase( (p->selFlags & (SF_Distinct|SF_Aggregate))==SF_Aggregate );
    return 0; /* No DISTINCT keyword and no aggregate functions */
  }
  assert( p->pGroupBy==0 );              /* Has no GROUP BY clause */
  if( p->pLimit ) return 0;              /* Has no LIMIT clause */
  assert( p->pOffset==0 );               /* No LIMIT means no OFFSET */
  if( p->pWhere ) return 0;              /* Has no WHERE clause */
  pSrc = p->pSrc;
  assert( pSrc!=0 );
  if( pSrc->nSrc!=1 ) return 0;          /* Single term in FROM clause */
  if( pSrc->a[0].pSelect ) return 0;     /* FROM is not a subquery or view */
  pTab = pSrc->a[0].pTab;
  assert( pTab!=0 );
  assert( pTab->pSelect==0 );            /* FROM clause is not a view */
  if( IsVirtual(pTab) ) return 0;        /* FROM clause not a virtual table */
  pEList = p->pEList;
  assert( pEList!=0 );
  /* All SELECT results must be columns. */
  for(i=0; i<pEList->nExpr; i++){
    Expr *pRes = pEList->a[i].pExpr;
    if( pRes->op!=TK_COLUMN ) return 0;
    assert( pRes->iTable==pSrc->a[0].iCursor );  /* Not a correlated subquery */
  }
  return p;
}
#endif /* SQLITE_OMIT_SUBQUERY */

#ifndef SQLITE_OMIT_SUBQUERY
/*
** Generate code that checks the left-most column of index table iCur to see if
** it contains any NULL entries.  Cause the register at regHasNull to be set
** to a non-NULL value if iCur contains no NULLs.  Cause register regHasNull
** to be set to NULL if iCur contains one or more NULL values.
*/
static void sqlite3SetHasNullFlag(Vdbe *v, int iCur, int regHasNull){
  int addr1;
  sqlite3VdbeAddOp2(v, OP_Integer, 0, regHasNull);
  addr1 = sqlite3VdbeAddOp1(v, OP_Rewind, iCur); VdbeCoverage(v);
  sqlite3VdbeAddOp3(v, OP_Column, iCur, 0, regHasNull);
  sqlite3VdbeChangeP5(v, OPFLAG_TYPEOFARG);
  VdbeComment((v, "first_entry_in(%d)", iCur));
  sqlite3VdbeJumpHere(v, addr1);
}
#endif


#ifndef SQLITE_OMIT_SUBQUERY
/*
** The argument is an IN operator with a list (not a subquery) on the 
** right-hand side.  Return TRUE if that list is constant.
*/
static int sqlite3InRhsIsConstant(Expr *pIn){
  Expr *pLHS;
  int res;
  assert( !ExprHasProperty(pIn, EP_xIsSelect) );
  pLHS = pIn->pLeft;
  pIn->pLeft = 0;
  res = sqlite3ExprIsConstant(pIn);
  pIn->pLeft = pLHS;
  return res;
}
#endif

/*
** This function is used by the implementation of the IN (...) operator.
** The pX parameter is the expression on the RHS of the IN operator, which
** might be either a list of expressions or a subquery.
**
** The job of this routine is to find or create a b-tree object that can
** be used either to test for membership in the RHS set or to iterate through
** all members of the RHS set, skipping duplicates.
**
** A cursor is opened on the b-tree object that is the RHS of the IN operator
** and pX->iTable is set to the index of that cursor.
**
** The returned value of this function indicates the b-tree type, as follows:
**
**   IN_INDEX_ROWID      - The cursor was opened on a database table.
**   IN_INDEX_INDEX_ASC  - The cursor was opened on an ascending index.
**   IN_INDEX_INDEX_DESC - The cursor was opened on a descending index.
**   IN_INDEX_EPH        - The cursor was opened on a specially created and
**                         populated epheremal table.
**   IN_INDEX_NOOP       - No cursor was allocated.  The IN operator must be
**                         implemented as a sequence of comparisons.
**
** An existing b-tree might be used if the RHS expression pX is a simple
** subquery such as:
**
**     SELECT <column1>, <column2>... FROM <table>
**
** If the RHS of the IN operator is a list or a more complex subquery, then
** an ephemeral table might need to be generated from the RHS and then
** pX->iTable made to point to the ephemeral table instead of an
** existing table.
**
** The inFlags parameter must contain exactly one of the bits
** IN_INDEX_MEMBERSHIP or IN_INDEX_LOOP.  If inFlags contains
** IN_INDEX_MEMBERSHIP, then the generated table will be used for a
** fast membership test.  When the IN_INDEX_LOOP bit is set, the
** IN index will be used to loop over all values of the RHS of the
** IN operator.
**
** When IN_INDEX_LOOP is used (and the b-tree will be used to iterate
** through the set members) then the b-tree must not contain duplicates.
** An epheremal table must be used unless the selected columns are guaranteed
** to be unique - either because it is an INTEGER PRIMARY KEY or due to
** a UNIQUE constraint or index.
**
** When IN_INDEX_MEMBERSHIP is used (and the b-tree will be used 
** for fast set membership tests) then an epheremal table must 
** be used unless <columns> is a single INTEGER PRIMARY KEY column or an 
** index can be found with the specified <columns> as its left-most.
**
** If the IN_INDEX_NOOP_OK and IN_INDEX_MEMBERSHIP are both set and
** if the RHS of the IN operator is a list (not a subquery) then this
** routine might decide that creating an ephemeral b-tree for membership
** testing is too expensive and return IN_INDEX_NOOP.  In that case, the
** calling routine should implement the IN operator using a sequence
** of Eq or Ne comparison operations.
**
** When the b-tree is being used for membership tests, the calling function
** might need to know whether or not the RHS side of the IN operator
** contains a NULL.  If prRhsHasNull is not a NULL pointer and 
** if there is any chance that the (...) might contain a NULL value at
** runtime, then a register is allocated and the register number written
** to *prRhsHasNull. If there is no chance that the (...) contains a
** NULL value, then *prRhsHasNull is left unchanged.
**
** If a register is allocated and its location stored in *prRhsHasNull, then
** the value in that register will be NULL if the b-tree contains one or more
** NULL values, and it will be some non-NULL value if the b-tree contains no
** NULL values.
**
** If the aiMap parameter is not NULL, it must point to an array containing
** one element for each column returned by the SELECT statement on the RHS
** of the IN(...) operator. The i'th entry of the array is populated with the
** offset of the index column that matches the i'th column returned by the
** SELECT. For example, if the expression and selected index are:
**
**   (?,?,?) IN (SELECT a, b, c FROM t1)
**   CREATE INDEX i1 ON t1(b, c, a);
**
** then aiMap[] is populated with {2, 0, 1}.
*/
#ifndef SQLITE_OMIT_SUBQUERY
int sqlite3FindInIndex(
  Parse *pParse,             /* Parsing context */
  Expr *pX,                  /* The right-hand side (RHS) of the IN operator */
  u32 inFlags,               /* IN_INDEX_LOOP, _MEMBERSHIP, and/or _NOOP_OK */
  int *prRhsHasNull,         /* Register holding NULL status.  See notes */
  int *aiMap                 /* Mapping from Index fields to RHS fields */
){
  Select *p;                            /* SELECT to the right of IN operator */
  int eType = 0;                        /* Type of RHS table. IN_INDEX_* */
  int iTab = pParse->nTab++;            /* Cursor of the RHS table */
  int mustBeUnique;                     /* True if RHS must be unique */
  Vdbe *v = sqlite3GetVdbe(pParse);     /* Virtual machine being coded */

  assert( pX->op==TK_IN );
  mustBeUnique = (inFlags & IN_INDEX_LOOP)!=0;

  /* If the RHS of this IN(...) operator is a SELECT, and if it matters 
  ** whether or not the SELECT result contains NULL values, check whether
  ** or not NULL is actually possible (it may not be, for example, due 
  ** to NOT NULL constraints in the schema). If no NULL values are possible,
  ** set prRhsHasNull to 0 before continuing.  */
  if( prRhsHasNull && (pX->flags & EP_xIsSelect) ){
    int i;
    ExprList *pEList = pX->x.pSelect->pEList;
    for(i=0; i<pEList->nExpr; i++){
      if( sqlite3ExprCanBeNull(pEList->a[i].pExpr) ) break;
    }
    if( i==pEList->nExpr ){
      prRhsHasNull = 0;
    }
  }

  /* Check to see if an existing table or index can be used to
  ** satisfy the query.  This is preferable to generating a new 
  ** ephemeral table.  */
  if( pParse->nErr==0 && (p = isCandidateForInOpt(pX))!=0 ){
    sqlite3 *db = pParse->db;              /* Database connection */
    Table *pTab;                           /* Table <table>. */
    i16 iDb;                               /* Database idx for pTab */
    ExprList *pEList = p->pEList;
    int nExpr = pEList->nExpr;

    assert( p->pEList!=0 );             /* Because of isCandidateForInOpt(p) */
    assert( p->pEList->a[0].pExpr!=0 ); /* Because of isCandidateForInOpt(p) */
    assert( p->pSrc!=0 );               /* Because of isCandidateForInOpt(p) */
    pTab = p->pSrc->a[0].pTab;

    /* Code an OP_Transaction and OP_TableLock for <table>. */
    iDb = sqlite3SchemaToIndex(db, pTab->pSchema);
    sqlite3CodeVerifySchema(pParse, iDb);
    sqlite3TableLock(pParse, iDb, pTab->tnum, 0, pTab->zName);

    assert(v);  /* sqlite3GetVdbe() has always been previously called */
    if( nExpr==1 && pEList->a[0].pExpr->iColumn<0 ){
      /* The "x IN (SELECT rowid FROM table)" case */
      int iAddr = sqlite3VdbeAddOp0(v, OP_Once);
      VdbeCoverage(v);

      sqlite3OpenTable(pParse, iTab, iDb, pTab, OP_OpenRead);
      eType = IN_INDEX_ROWID;

      sqlite3VdbeJumpHere(v, iAddr);
    }else{
      Index *pIdx;                         /* Iterator variable */
      int affinity_ok = 1;
      int i;

      /* Check that the affinity that will be used to perform each 
      ** comparison is the same as the affinity of each column in table
      ** on the RHS of the IN operator.  If it not, it is not possible to
      ** use any index of the RHS table.  */
      for(i=0; i<nExpr && affinity_ok; i++){
        Expr *pLhs = sqlite3VectorFieldSubexpr(pX->pLeft, i);
        int iCol = pEList->a[i].pExpr->iColumn;
        char idxaff = sqlite3TableColumnAffinity(pTab,iCol); /* RHS table */
        char cmpaff = sqlite3CompareAffinity(pLhs, idxaff);
        testcase( cmpaff==SQLITE_AFF_BLOB );
        testcase( cmpaff==SQLITE_AFF_TEXT );
        switch( cmpaff ){
          case SQLITE_AFF_BLOB:
            break;
          case SQLITE_AFF_TEXT:
            /* sqlite3CompareAffinity() only returns TEXT if one side or the
            ** other has no affinity and the other side is TEXT.  Hence,
            ** the only way for cmpaff to be TEXT is for idxaff to be TEXT
            ** and for the term on the LHS of the IN to have no affinity. */
            assert( idxaff==SQLITE_AFF_TEXT );
            break;
          default:
            affinity_ok = sqlite3IsNumericAffinity(idxaff);
        }
      }

      if( affinity_ok ){
        /* Search for an existing index that will work for this IN operator */
        for(pIdx=pTab->pIndex; pIdx && eType==0; pIdx=pIdx->pNext){
          Bitmask colUsed;      /* Columns of the index used */
          Bitmask mCol;         /* Mask for the current column */
          if( pIdx->nColumn<nExpr ) continue;
          /* Maximum nColumn is BMS-2, not BMS-1, so that we can compute
          ** BITMASK(nExpr) without overflowing */
          testcase( pIdx->nColumn==BMS-2 );
          testcase( pIdx->nColumn==BMS-1 );
          if( pIdx->nColumn>=BMS-1 ) continue;
          if( mustBeUnique ){
            if( pIdx->nKeyCol>nExpr
             ||(pIdx->nColumn>nExpr && !IsUniqueIndex(pIdx))
            ){
              continue;  /* This index is not unique over the IN RHS columns */
            }
          }
  
          colUsed = 0;   /* Columns of index used so far */
          for(i=0; i<nExpr; i++){
            Expr *pLhs = sqlite3VectorFieldSubexpr(pX->pLeft, i);
            Expr *pRhs = pEList->a[i].pExpr;
            CollSeq *pReq = sqlite3BinaryCompareCollSeq(pParse, pLhs, pRhs);
            int j;
  
            assert( pReq!=0 || pRhs->iColumn==XN_ROWID || pParse->nErr );
            for(j=0; j<nExpr; j++){
              if( pIdx->aiColumn[j]!=pRhs->iColumn ) continue;
              assert( pIdx->azColl[j] );
              if( pReq!=0 && sqlite3StrICmp(pReq->zName, pIdx->azColl[j])!=0 ){
                continue;
              }
              break;
            }
            if( j==nExpr ) break;
            mCol = MASKBIT(j);
            if( mCol & colUsed ) break; /* Each column used only once */
            colUsed |= mCol;
            if( aiMap ) aiMap[i] = j;
          }
  
          assert( i==nExpr || colUsed!=(MASKBIT(nExpr)-1) );
          if( colUsed==(MASKBIT(nExpr)-1) ){
            /* If we reach this point, that means the index pIdx is usable */
            int iAddr = sqlite3VdbeAddOp0(v, OP_Once); VdbeCoverage(v);
#ifndef SQLITE_OMIT_EXPLAIN
            sqlite3VdbeAddOp4(v, OP_Explain, 0, 0, 0,
              sqlite3MPrintf(db, "USING INDEX %s FOR IN-OPERATOR",pIdx->zName),
              P4_DYNAMIC);
#endif
            sqlite3VdbeAddOp3(v, OP_OpenRead, iTab, pIdx->tnum, iDb);
            sqlite3VdbeSetP4KeyInfo(pParse, pIdx);
            VdbeComment((v, "%s", pIdx->zName));
            assert( IN_INDEX_INDEX_DESC == IN_INDEX_INDEX_ASC+1 );
            eType = IN_INDEX_INDEX_ASC + pIdx->aSortOrder[0];
  
            if( prRhsHasNull ){
#ifdef SQLITE_ENABLE_COLUMN_USED_MASK
              i64 mask = (1<<nExpr)-1;
              sqlite3VdbeAddOp4Dup8(v, OP_ColumnsUsed, 
                  iTab, 0, 0, (u8*)&mask, P4_INT64);
#endif
              *prRhsHasNull = ++pParse->nMem;
              if( nExpr==1 ){
                sqlite3SetHasNullFlag(v, iTab, *prRhsHasNull);
              }
            }
            sqlite3VdbeJumpHere(v, iAddr);
          }
        } /* End loop over indexes */
      } /* End if( affinity_ok ) */
    } /* End if not an rowid index */
  } /* End attempt to optimize using an index */

  /* If no preexisting index is available for the IN clause
  ** and IN_INDEX_NOOP is an allowed reply
  ** and the RHS of the IN operator is a list, not a subquery
  ** and the RHS is not constant or has two or fewer terms,
  ** then it is not worth creating an ephemeral table to evaluate
  ** the IN operator so return IN_INDEX_NOOP.
  */
  if( eType==0
   && (inFlags & IN_INDEX_NOOP_OK)
   && !ExprHasProperty(pX, EP_xIsSelect)
   && (!sqlite3InRhsIsConstant(pX) || pX->x.pList->nExpr<=2)
  ){
    eType = IN_INDEX_NOOP;
  }

  if( eType==0 ){
    /* Could not find an existing table or index to use as the RHS b-tree.
    ** We will have to generate an ephemeral table to do the job.
    */
    u32 savedNQueryLoop = pParse->nQueryLoop;
    int rMayHaveNull = 0;
    eType = IN_INDEX_EPH;
    if( inFlags & IN_INDEX_LOOP ){
      pParse->nQueryLoop = 0;
      if( pX->pLeft->iColumn<0 && !ExprHasProperty(pX, EP_xIsSelect) ){
        eType = IN_INDEX_ROWID;
      }
    }else if( prRhsHasNull ){
      *prRhsHasNull = rMayHaveNull = ++pParse->nMem;
    }
    sqlite3CodeSubselect(pParse, pX, rMayHaveNull, eType==IN_INDEX_ROWID);
    pParse->nQueryLoop = savedNQueryLoop;
  }else{
    pX->iTable = iTab;
  }

  if( aiMap && eType!=IN_INDEX_INDEX_ASC && eType!=IN_INDEX_INDEX_DESC ){
    int i, n;
    n = sqlite3ExprVectorSize(pX->pLeft);
    for(i=0; i<n; i++) aiMap[i] = i;
  }
  return eType;
}
#endif

#ifndef SQLITE_OMIT_SUBQUERY
/*
** Argument pExpr is an (?, ?...) IN(...) expression. This 
** function allocates and returns a nul-terminated string containing 
** the affinities to be used for each column of the comparison.
**
** It is the responsibility of the caller to ensure that the returned
** string is eventually freed using sqlite3DbFree().
*/
static char *exprINAffinity(Parse *pParse, Expr *pExpr){
  Expr *pLeft = pExpr->pLeft;
  int nVal = sqlite3ExprVectorSize(pLeft);
  Select *pSelect = (pExpr->flags & EP_xIsSelect) ? pExpr->x.pSelect : 0;
  char *zRet;

  assert( pExpr->op==TK_IN );
  zRet = sqlite3DbMallocRaw(pParse->db, nVal+1);
  if( zRet ){
    int i;
    for(i=0; i<nVal; i++){
      Expr *pA = sqlite3VectorFieldSubexpr(pLeft, i);
      char a = sqlite3ExprAffinity(pA);
      if( pSelect ){
        zRet[i] = sqlite3CompareAffinity(pSelect->pEList->a[i].pExpr, a);
      }else{
        zRet[i] = a;
      }
    }
    zRet[nVal] = '\0';
  }
  return zRet;
}
#endif

#ifndef SQLITE_OMIT_SUBQUERY
/*
** Load the Parse object passed as the first argument with an error 
** message of the form:
**
**   "sub-select returns N columns - expected M"
*/   
void sqlite3SubselectError(Parse *pParse, int nActual, int nExpect){
  const char *zFmt = "sub-select returns %d columns - expected %d";
  sqlite3ErrorMsg(pParse, zFmt, nActual, nExpect);
}
#endif

/*
** Expression pExpr is a vector that has been used in a context where
** it is not permitted. If pExpr is a sub-select vector, this routine 
** loads the Parse object with a message of the form:
**
**   "sub-select returns N columns - expected 1"
**
** Or, if it is a regular scalar vector:
**
**   "row value misused"
*/   
void sqlite3VectorErrorMsg(Parse *pParse, Expr *pExpr){
#ifndef SQLITE_OMIT_SUBQUERY
  if( pExpr->flags & EP_xIsSelect ){
    sqlite3SubselectError(pParse, pExpr->x.pSelect->pEList->nExpr, 1);
  }else
#endif
  {
    sqlite3ErrorMsg(pParse, "row value misused");
  }
}

/*
** Generate code for scalar subqueries used as a subquery expression, EXISTS,
** or IN operators.  Examples:
**
**     (SELECT a FROM b)          -- subquery
**     EXISTS (SELECT a FROM b)   -- EXISTS subquery
**     x IN (4,5,11)              -- IN operator with list on right-hand side
**     x IN (SELECT a FROM b)     -- IN operator with subquery on the right
**
** The pExpr parameter describes the expression that contains the IN
** operator or subquery.
**
** If parameter isRowid is non-zero, then expression pExpr is guaranteed
** to be of the form "<rowid> IN (?, ?, ?)", where <rowid> is a reference
** to some integer key column of a table B-Tree. In this case, use an
** intkey B-Tree to store the set of IN(...) values instead of the usual
** (slower) variable length keys B-Tree.
**
** If rMayHaveNull is non-zero, that means that the operation is an IN
** (not a SELECT or EXISTS) and that the RHS might contains NULLs.
** All this routine does is initialize the register given by rMayHaveNull
** to NULL.  Calling routines will take care of changing this register
** value to non-NULL if the RHS is NULL-free.
**
** For a SELECT or EXISTS operator, return the register that holds the
** result.  For a multi-column SELECT, the result is stored in a contiguous
** array of registers and the return value is the register of the left-most
** result column.  Return 0 for IN operators or if an error occurs.
*/
#ifndef SQLITE_OMIT_SUBQUERY
int sqlite3CodeSubselect(
  Parse *pParse,          /* Parsing context */
  Expr *pExpr,            /* The IN, SELECT, or EXISTS operator */
  int rHasNullFlag,       /* Register that records whether NULLs exist in RHS */
  int isRowid             /* If true, LHS of IN operator is a rowid */
){
  int jmpIfDynamic = -1;                      /* One-time test address */
  int rReg = 0;                           /* Register storing resulting */
  Vdbe *v = sqlite3GetVdbe(pParse);
  if( NEVER(v==0) ) return 0;
  sqlite3ExprCachePush(pParse);

  /* The evaluation of the IN/EXISTS/SELECT must be repeated every time it
  ** is encountered if any of the following is true:
  **
  **    *  The right-hand side is a correlated subquery
  **    *  The right-hand side is an expression list containing variables
  **    *  We are inside a trigger
  **
  ** If all of the above are false, then we can run this code just once
  ** save the results, and reuse the same result on subsequent invocations.
  */
  if( !ExprHasProperty(pExpr, EP_VarSelect) ){
    jmpIfDynamic = sqlite3VdbeAddOp0(v, OP_Once); VdbeCoverage(v);
  }

#ifndef SQLITE_OMIT_EXPLAIN
  if( pParse->explain==2 ){
    char *zMsg = sqlite3MPrintf(pParse->db, "EXECUTE %s%s SUBQUERY %d",
        jmpIfDynamic>=0?"":"CORRELATED ",
        pExpr->op==TK_IN?"LIST":"SCALAR",
        pParse->iNextSelectId
    );
    sqlite3VdbeAddOp4(v, OP_Explain, pParse->iSelectId, 0, 0, zMsg, P4_DYNAMIC);
  }
#endif

  switch( pExpr->op ){
    case TK_IN: {
      int addr;                   /* Address of OP_OpenEphemeral instruction */
      Expr *pLeft = pExpr->pLeft; /* the LHS of the IN operator */
      KeyInfo *pKeyInfo = 0;      /* Key information */
      int nVal;                   /* Size of vector pLeft */
      
      nVal = sqlite3ExprVectorSize(pLeft);
      assert( !isRowid || nVal==1 );

      /* Whether this is an 'x IN(SELECT...)' or an 'x IN(<exprlist>)'
      ** expression it is handled the same way.  An ephemeral table is 
      ** filled with index keys representing the results from the 
      ** SELECT or the <exprlist>.
      **
      ** If the 'x' expression is a column value, or the SELECT...
      ** statement returns a column value, then the affinity of that
      ** column is used to build the index keys. If both 'x' and the
      ** SELECT... statement are columns, then numeric affinity is used
      ** if either column has NUMERIC or INTEGER affinity. If neither
      ** 'x' nor the SELECT... statement are columns, then numeric affinity
      ** is used.
      */
      pExpr->iTable = pParse->nTab++;
      addr = sqlite3VdbeAddOp2(v, OP_OpenEphemeral, 
          pExpr->iTable, (isRowid?0:nVal));
      pKeyInfo = isRowid ? 0 : sqlite3KeyInfoAlloc(pParse->db, nVal, 1);

      if( ExprHasProperty(pExpr, EP_xIsSelect) ){
        /* Case 1:     expr IN (SELECT ...)
        **
        ** Generate code to write the results of the select into the temporary
        ** table allocated and opened above.
        */
        Select *pSelect = pExpr->x.pSelect;
        ExprList *pEList = pSelect->pEList;

        assert( !isRowid );
        /* If the LHS and RHS of the IN operator do not match, that
        ** error will have been caught long before we reach this point. */
        if( ALWAYS(pEList->nExpr==nVal) ){
          SelectDest dest;
          int i;
          sqlite3SelectDestInit(&dest, SRT_Set, pExpr->iTable);
          dest.zAffSdst = exprINAffinity(pParse, pExpr);
          pSelect->iLimit = 0;
          testcase( pSelect->selFlags & SF_Distinct );
          testcase( pKeyInfo==0 ); /* Caused by OOM in sqlite3KeyInfoAlloc() */
          if( sqlite3Select(pParse, pSelect, &dest) ){
            sqlite3DbFree(pParse->db, dest.zAffSdst);
            sqlite3KeyInfoUnref(pKeyInfo);
            return 0;
          }
          sqlite3DbFree(pParse->db, dest.zAffSdst);
          assert( pKeyInfo!=0 ); /* OOM will cause exit after sqlite3Select() */
          assert( pEList!=0 );
          assert( pEList->nExpr>0 );
          assert( sqlite3KeyInfoIsWriteable(pKeyInfo) );
          for(i=0; i<nVal; i++){
            Expr *p = sqlite3VectorFieldSubexpr(pLeft, i);
            pKeyInfo->aColl[i] = sqlite3BinaryCompareCollSeq(
                pParse, p, pEList->a[i].pExpr
            );
          }
        }
      }else if( ALWAYS(pExpr->x.pList!=0) ){
        /* Case 2:     expr IN (exprlist)
        **
        ** For each expression, build an index key from the evaluation and
        ** store it in the temporary table. If <expr> is a column, then use
        ** that columns affinity when building index keys. If <expr> is not
        ** a column, use numeric affinity.
        */
        char affinity;            /* Affinity of the LHS of the IN */
        int i;
        ExprList *pList = pExpr->x.pList;
        struct ExprList_item *pItem;
        int r1, r2, r3;

        affinity = sqlite3ExprAffinity(pLeft);
        if( !affinity ){
          affinity = SQLITE_AFF_BLOB;
        }
        if( pKeyInfo ){
          assert( sqlite3KeyInfoIsWriteable(pKeyInfo) );
          pKeyInfo->aColl[0] = sqlite3ExprCollSeq(pParse, pExpr->pLeft);
        }

        /* Loop through each expression in <exprlist>. */
        r1 = sqlite3GetTempReg(pParse);
        r2 = sqlite3GetTempReg(pParse);
        if( isRowid ) sqlite3VdbeAddOp2(v, OP_Null, 0, r2);
        for(i=pList->nExpr, pItem=pList->a; i>0; i--, pItem++){
          Expr *pE2 = pItem->pExpr;
          int iValToIns;

          /* If the expression is not constant then we will need to
          ** disable the test that was generated above that makes sure
          ** this code only executes once.  Because for a non-constant
          ** expression we need to rerun this code each time.
          */
          if( jmpIfDynamic>=0 && !sqlite3ExprIsConstant(pE2) ){
            sqlite3VdbeChangeToNoop(v, jmpIfDynamic);
            jmpIfDynamic = -1;
          }

          /* Evaluate the expression and insert it into the temp table */
          if( isRowid && sqlite3ExprIsInteger(pE2, &iValToIns) ){
            sqlite3VdbeAddOp3(v, OP_InsertInt, pExpr->iTable, r2, iValToIns);
          }else{
            r3 = sqlite3ExprCodeTarget(pParse, pE2, r1);
            if( isRowid ){
              sqlite3VdbeAddOp2(v, OP_MustBeInt, r3,
                                sqlite3VdbeCurrentAddr(v)+2);
              VdbeCoverage(v);
              sqlite3VdbeAddOp3(v, OP_Insert, pExpr->iTable, r2, r3);
            }else{
              sqlite3VdbeAddOp4(v, OP_MakeRecord, r3, 1, r2, &affinity, 1);
              sqlite3ExprCacheAffinityChange(pParse, r3, 1);
              sqlite3VdbeAddOp4Int(v, OP_IdxInsert, pExpr->iTable, r2, r3, 1);
            }
          }
        }
        sqlite3ReleaseTempReg(pParse, r1);
        sqlite3ReleaseTempReg(pParse, r2);
      }
      if( pKeyInfo ){
        sqlite3VdbeChangeP4(v, addr, (void *)pKeyInfo, P4_KEYINFO);
      }
      break;
    }

    case TK_EXISTS:
    case TK_SELECT:
    default: {
      /* Case 3:    (SELECT ... FROM ...)
      **     or:    EXISTS(SELECT ... FROM ...)
      **
      ** For a SELECT, generate code to put the values for all columns of
      ** the first row into an array of registers and return the index of
      ** the first register.
      **
      ** If this is an EXISTS, write an integer 0 (not exists) or 1 (exists)
      ** into a register and return that register number.
      **
      ** In both cases, the query is augmented with "LIMIT 1".  Any 
      ** preexisting limit is discarded in place of the new LIMIT 1.
      */
      Select *pSel;                         /* SELECT statement to encode */
      SelectDest dest;                      /* How to deal with SELECT result */
      int nReg;                             /* Registers to allocate */

      testcase( pExpr->op==TK_EXISTS );
      testcase( pExpr->op==TK_SELECT );
      assert( pExpr->op==TK_EXISTS || pExpr->op==TK_SELECT );
      assert( ExprHasProperty(pExpr, EP_xIsSelect) );

      pSel = pExpr->x.pSelect;
      nReg = pExpr->op==TK_SELECT ? pSel->pEList->nExpr : 1;
      sqlite3SelectDestInit(&dest, 0, pParse->nMem+1);
      pParse->nMem += nReg;
      if( pExpr->op==TK_SELECT ){
        dest.eDest = SRT_Mem;
        dest.iSdst = dest.iSDParm;
        dest.nSdst = nReg;
        sqlite3VdbeAddOp3(v, OP_Null, 0, dest.iSDParm, dest.iSDParm+nReg-1);
        VdbeComment((v, "Init subquery result"));
      }else{
        dest.eDest = SRT_Exists;
        sqlite3VdbeAddOp2(v, OP_Integer, 0, dest.iSDParm);
        VdbeComment((v, "Init EXISTS result"));
      }
      sqlite3ExprDelete(pParse->db, pSel->pLimit);
      pSel->pLimit = sqlite3ExprAlloc(pParse->db, TK_INTEGER,
                                  &sqlite3IntTokens[1], 0);
      pSel->iLimit = 0;
      pSel->selFlags &= ~SF_MultiValue;
      if( sqlite3Select(pParse, pSel, &dest) ){
        return 0;
      }
      rReg = dest.iSDParm;
      ExprSetVVAProperty(pExpr, EP_NoReduce);
      break;
    }
  }

  if( rHasNullFlag ){
    sqlite3SetHasNullFlag(v, pExpr->iTable, rHasNullFlag);
  }

  if( jmpIfDynamic>=0 ){
    sqlite3VdbeJumpHere(v, jmpIfDynamic);
  }
  sqlite3ExprCachePop(pParse);

  return rReg;
}
#endif /* SQLITE_OMIT_SUBQUERY */

#ifndef SQLITE_OMIT_SUBQUERY
/*
** Expr pIn is an IN(...) expression. This function checks that the 
** sub-select on the RHS of the IN() operator has the same number of 
** columns as the vector on the LHS. Or, if the RHS of the IN() is not 
** a sub-query, that the LHS is a vector of size 1.
*/
int sqlite3ExprCheckIN(Parse *pParse, Expr *pIn){
  int nVector = sqlite3ExprVectorSize(pIn->pLeft);
  if( (pIn->flags & EP_xIsSelect) ){
    if( nVector!=pIn->x.pSelect->pEList->nExpr ){
      sqlite3SubselectError(pParse, pIn->x.pSelect->pEList->nExpr, nVector);
      return 1;
    }
  }else if( nVector!=1 ){
    sqlite3VectorErrorMsg(pParse, pIn->pLeft);
    return 1;
  }
  return 0;
}
#endif

#ifndef SQLITE_OMIT_SUBQUERY
/*
** Generate code for an IN expression.
**
**      x IN (SELECT ...)
**      x IN (value, value, ...)
**
** The left-hand side (LHS) is a scalar or vector expression.  The 
** right-hand side (RHS) is an array of zero or more scalar values, or a
** subquery.  If the RHS is a subquery, the number of result columns must
** match the number of columns in the vector on the LHS.  If the RHS is
** a list of values, the LHS must be a scalar. 
**
** The IN operator is true if the LHS value is contained within the RHS.
** The result is false if the LHS is definitely not in the RHS.  The 
** result is NULL if the presence of the LHS in the RHS cannot be 
** determined due to NULLs.
**
** This routine generates code that jumps to destIfFalse if the LHS is not 
** contained within the RHS.  If due to NULLs we cannot determine if the LHS
** is contained in the RHS then jump to destIfNull.  If the LHS is contained
** within the RHS then fall through.
**
** See the separate in-operator.md documentation file in the canonical
** SQLite source tree for additional information.
*/
static void sqlite3ExprCodeIN(
  Parse *pParse,        /* Parsing and code generating context */
  Expr *pExpr,          /* The IN expression */
  int destIfFalse,      /* Jump here if LHS is not contained in the RHS */
  int destIfNull        /* Jump here if the results are unknown due to NULLs */
){
  int rRhsHasNull = 0;  /* Register that is true if RHS contains NULL values */
  int eType;            /* Type of the RHS */
  int rLhs;             /* Register(s) holding the LHS values */
  int rLhsOrig;         /* LHS values prior to reordering by aiMap[] */
  Vdbe *v;              /* Statement under construction */
  int *aiMap = 0;       /* Map from vector field to index column */
  char *zAff = 0;       /* Affinity string for comparisons */
  int nVector;          /* Size of vectors for this IN operator */
  int iDummy;           /* Dummy parameter to exprCodeVector() */
  Expr *pLeft;          /* The LHS of the IN operator */
  int i;                /* loop counter */
  int destStep2;        /* Where to jump when NULLs seen in step 2 */
  int destStep6 = 0;    /* Start of code for Step 6 */
  int addrTruthOp;      /* Address of opcode that determines the IN is true */
  int destNotNull;      /* Jump here if a comparison is not true in step 6 */
  int addrTop;          /* Top of the step-6 loop */ 

  pLeft = pExpr->pLeft;
  if( sqlite3ExprCheckIN(pParse, pExpr) ) return;
  zAff = exprINAffinity(pParse, pExpr);
  nVector = sqlite3ExprVectorSize(pExpr->pLeft);
  aiMap = (int*)sqlite3DbMallocZero(
      pParse->db, nVector*(sizeof(int) + sizeof(char)) + 1
  );
  if( pParse->db->mallocFailed ) goto sqlite3ExprCodeIN_oom_error;

  /* Attempt to compute the RHS. After this step, if anything other than
  ** IN_INDEX_NOOP is returned, the table opened ith cursor pExpr->iTable 
  ** contains the values that make up the RHS. If IN_INDEX_NOOP is returned,
  ** the RHS has not yet been coded.  */
  v = pParse->pVdbe;
  assert( v!=0 );       /* OOM detected prior to this routine */
  VdbeNoopComment((v, "begin IN expr"));
  eType = sqlite3FindInIndex(pParse, pExpr,
                             IN_INDEX_MEMBERSHIP | IN_INDEX_NOOP_OK,
                             destIfFalse==destIfNull ? 0 : &rRhsHasNull, aiMap);

  assert( pParse->nErr || nVector==1 || eType==IN_INDEX_EPH
       || eType==IN_INDEX_INDEX_ASC || eType==IN_INDEX_INDEX_DESC 
  );
#ifdef SQLITE_DEBUG
  /* Confirm that aiMap[] contains nVector integer values between 0 and
  ** nVector-1. */
  for(i=0; i<nVector; i++){
    int j, cnt;
    for(cnt=j=0; j<nVector; j++) if( aiMap[j]==i ) cnt++;
    assert( cnt==1 );
  }
#endif

  /* Code the LHS, the <expr> from "<expr> IN (...)". If the LHS is a 
  ** vector, then it is stored in an array of nVector registers starting 
  ** at r1.
  **
  ** sqlite3FindInIndex() might have reordered the fields of the LHS vector
  ** so that the fields are in the same order as an existing index.   The
  ** aiMap[] array contains a mapping from the original LHS field order to
  ** the field order that matches the RHS index.
  */
  sqlite3ExprCachePush(pParse);
  rLhsOrig = exprCodeVector(pParse, pLeft, &iDummy);
  for(i=0; i<nVector && aiMap[i]==i; i++){} /* Are LHS fields reordered? */
  if( i==nVector ){
    /* LHS fields are not reordered */
    rLhs = rLhsOrig;
  }else{
    /* Need to reorder the LHS fields according to aiMap */
    rLhs = sqlite3GetTempRange(pParse, nVector);
    for(i=0; i<nVector; i++){
      sqlite3VdbeAddOp3(v, OP_Copy, rLhsOrig+i, rLhs+aiMap[i], 0);
    }
  }

  /* If sqlite3FindInIndex() did not find or create an index that is
  ** suitable for evaluating the IN operator, then evaluate using a
  ** sequence of comparisons.
  **
  ** This is step (1) in the in-operator.md optimized algorithm.
  */
  if( eType==IN_INDEX_NOOP ){
    ExprList *pList = pExpr->x.pList;
    CollSeq *pColl = sqlite3ExprCollSeq(pParse, pExpr->pLeft);
    int labelOk = sqlite3VdbeMakeLabel(v);
    int r2, regToFree;
    int regCkNull = 0;
    int ii;
    assert( !ExprHasProperty(pExpr, EP_xIsSelect) );
    if( destIfNull!=destIfFalse ){
      regCkNull = sqlite3GetTempReg(pParse);
      sqlite3VdbeAddOp3(v, OP_BitAnd, rLhs, rLhs, regCkNull);
    }
    for(ii=0; ii<pList->nExpr; ii++){
      r2 = sqlite3ExprCodeTemp(pParse, pList->a[ii].pExpr, &regToFree);
      if( regCkNull && sqlite3ExprCanBeNull(pList->a[ii].pExpr) ){
        sqlite3VdbeAddOp3(v, OP_BitAnd, regCkNull, r2, regCkNull);
      }
      if( ii<pList->nExpr-1 || destIfNull!=destIfFalse ){
        sqlite3VdbeAddOp4(v, OP_Eq, rLhs, labelOk, r2,
                          (void*)pColl, P4_COLLSEQ);
        VdbeCoverageIf(v, ii<pList->nExpr-1);
        VdbeCoverageIf(v, ii==pList->nExpr-1);
        sqlite3VdbeChangeP5(v, zAff[0]);
      }else{
        assert( destIfNull==destIfFalse );
        sqlite3VdbeAddOp4(v, OP_Ne, rLhs, destIfFalse, r2,
                          (void*)pColl, P4_COLLSEQ); VdbeCoverage(v);
        sqlite3VdbeChangeP5(v, zAff[0] | SQLITE_JUMPIFNULL);
      }
      sqlite3ReleaseTempReg(pParse, regToFree);
    }
    if( regCkNull ){
      sqlite3VdbeAddOp2(v, OP_IsNull, regCkNull, destIfNull); VdbeCoverage(v);
      sqlite3VdbeGoto(v, destIfFalse);
    }
    sqlite3VdbeResolveLabel(v, labelOk);
    sqlite3ReleaseTempReg(pParse, regCkNull);
    goto sqlite3ExprCodeIN_finished;
  }

  /* Step 2: Check to see if the LHS contains any NULL columns.  If the
  ** LHS does contain NULLs then the result must be either FALSE or NULL.
  ** We will then skip the binary search of the RHS.
  */
  if( destIfNull==destIfFalse ){
    destStep2 = destIfFalse;
  }else{
    destStep2 = destStep6 = sqlite3VdbeMakeLabel(v);
  }
  for(i=0; i<nVector; i++){
    Expr *p = sqlite3VectorFieldSubexpr(pExpr->pLeft, i);
    if( sqlite3ExprCanBeNull(p) ){
      sqlite3VdbeAddOp2(v, OP_IsNull, rLhs+i, destStep2);
      VdbeCoverage(v);
    }
  }

  /* Step 3.  The LHS is now known to be non-NULL.  Do the binary search
  ** of the RHS using the LHS as a probe.  If found, the result is
  ** true.
  */
  if( eType==IN_INDEX_ROWID ){
    /* In this case, the RHS is the ROWID of table b-tree and so we also
    ** know that the RHS is non-NULL.  Hence, we combine steps 3 and 4
    ** into a single opcode. */
    sqlite3VdbeAddOp3(v, OP_SeekRowid, pExpr->iTable, destIfFalse, rLhs);
    VdbeCoverage(v);
    addrTruthOp = sqlite3VdbeAddOp0(v, OP_Goto);  /* Return True */
  }else{
    sqlite3VdbeAddOp4(v, OP_Affinity, rLhs, nVector, 0, zAff, nVector);
    if( destIfFalse==destIfNull ){
      /* Combine Step 3 and Step 5 into a single opcode */
      sqlite3VdbeAddOp4Int(v, OP_NotFound, pExpr->iTable, destIfFalse,
                           rLhs, nVector); VdbeCoverage(v);
      goto sqlite3ExprCodeIN_finished;
    }
    /* Ordinary Step 3, for the case where FALSE and NULL are distinct */
    addrTruthOp = sqlite3VdbeAddOp4Int(v, OP_Found, pExpr->iTable, 0,
                                      rLhs, nVector); VdbeCoverage(v);
  }

  /* Step 4.  If the RHS is known to be non-NULL and we did not find
  ** an match on the search above, then the result must be FALSE.
  */
  if( rRhsHasNull && nVector==1 ){
    sqlite3VdbeAddOp2(v, OP_NotNull, rRhsHasNull, destIfFalse);
    VdbeCoverage(v);
  }

  /* Step 5.  If we do not care about the difference between NULL and
  ** FALSE, then just return false. 
  */
  if( destIfFalse==destIfNull ) sqlite3VdbeGoto(v, destIfFalse);

  /* Step 6: Loop through rows of the RHS.  Compare each row to the LHS.
  ** If any comparison is NULL, then the result is NULL.  If all
  ** comparisons are FALSE then the final result is FALSE.
  **
  ** For a scalar LHS, it is sufficient to check just the first row
  ** of the RHS.
  */
  if( destStep6 ) sqlite3VdbeResolveLabel(v, destStep6);
  addrTop = sqlite3VdbeAddOp2(v, OP_Rewind, pExpr->iTable, destIfFalse);
  VdbeCoverage(v);
  if( nVector>1 ){
    destNotNull = sqlite3VdbeMakeLabel(v);
  }else{
    /* For nVector==1, combine steps 6 and 7 by immediately returning
    ** FALSE if the first comparison is not NULL */
    destNotNull = destIfFalse;
  }
  for(i=0; i<nVector; i++){
    Expr *p;
    CollSeq *pColl;
    int r3 = sqlite3GetTempReg(pParse);
    p = sqlite3VectorFieldSubexpr(pLeft, i);
    pColl = sqlite3ExprCollSeq(pParse, p);
    sqlite3VdbeAddOp3(v, OP_Column, pExpr->iTable, i, r3);
    sqlite3VdbeAddOp4(v, OP_Ne, rLhs+i, destNotNull, r3,
                      (void*)pColl, P4_COLLSEQ);
    VdbeCoverage(v);
    sqlite3ReleaseTempReg(pParse, r3);
  }
  sqlite3VdbeAddOp2(v, OP_Goto, 0, destIfNull);
  if( nVector>1 ){
    sqlite3VdbeResolveLabel(v, destNotNull);
    sqlite3VdbeAddOp2(v, OP_Next, pExpr->iTable, addrTop+1);
    VdbeCoverage(v);

    /* Step 7:  If we reach this point, we know that the result must
    ** be false. */
    sqlite3VdbeAddOp2(v, OP_Goto, 0, destIfFalse);
  }

  /* Jumps here in order to return true. */
  sqlite3VdbeJumpHere(v, addrTruthOp);

sqlite3ExprCodeIN_finished:
  if( rLhs!=rLhsOrig ) sqlite3ReleaseTempReg(pParse, rLhs);
  sqlite3ExprCachePop(pParse);
  VdbeComment((v, "end IN expr"));
sqlite3ExprCodeIN_oom_error:
  sqlite3DbFree(pParse->db, aiMap);
  sqlite3DbFree(pParse->db, zAff);
}
#endif /* SQLITE_OMIT_SUBQUERY */

#ifndef SQLITE_OMIT_FLOATING_POINT
/*
** Generate an instruction that will put the floating point
** value described by z[0..n-1] into register iMem.
**
** The z[] string will probably not be zero-terminated.  But the 
** z[n] character is guaranteed to be something that does not look
** like the continuation of the number.
*/
static void codeReal(Vdbe *v, const char *z, int negateFlag, int iMem){
  if( ALWAYS(z!=0) ){
    double value;
    sqlite3AtoF(z, &value, sqlite3Strlen30(z), SQLITE_UTF8);
    assert( !sqlite3IsNaN(value) ); /* The new AtoF never returns NaN */
    if( negateFlag ) value = -value;
    sqlite3VdbeAddOp4Dup8(v, OP_Real, 0, iMem, 0, (u8*)&value, P4_REAL);
  }
}
#endif


/*
** Generate an instruction that will put the integer describe by
** text z[0..n-1] into register iMem.
**
** Expr.u.zToken is always UTF8 and zero-terminated.
*/
static void codeInteger(Parse *pParse, Expr *pExpr, int negFlag, int iMem){
  Vdbe *v = pParse->pVdbe;
  if( pExpr->flags & EP_IntValue ){
    int i = pExpr->u.iValue;
    assert( i>=0 );
    if( negFlag ) i = -i;
    sqlite3VdbeAddOp2(v, OP_Integer, i, iMem);
  }else{
    int c;
    i64 value;
    const char *z = pExpr->u.zToken;
    assert( z!=0 );
    c = sqlite3DecOrHexToI64(z, &value);
    if( c==1 || (c==2 && !negFlag) || (negFlag && value==SMALLEST_INT64)){
#ifdef SQLITE_OMIT_FLOATING_POINT
      sqlite3ErrorMsg(pParse, "oversized integer: %s%s", negFlag ? "-" : "", z);
#else
#ifndef SQLITE_OMIT_HEX_INTEGER
      if( sqlite3_strnicmp(z,"0x",2)==0 ){
        sqlite3ErrorMsg(pParse, "hex literal too big: %s%s", negFlag?"-":"",z);
      }else
#endif
      {
        codeReal(v, z, negFlag, iMem);
      }
#endif
    }else{
      if( negFlag ){ value = c==2 ? SMALLEST_INT64 : -value; }
      sqlite3VdbeAddOp4Dup8(v, OP_Int64, 0, iMem, 0, (u8*)&value, P4_INT64);
    }
  }
}

/*
** Erase column-cache entry number i
*/
static void cacheEntryClear(Parse *pParse, int i){
  if( pParse->aColCache[i].tempReg ){
    if( pParse->nTempReg<ArraySize(pParse->aTempReg) ){
      pParse->aTempReg[pParse->nTempReg++] = pParse->aColCache[i].iReg;
    }
  }
  pParse->nColCache--;
  if( i<pParse->nColCache ){
    pParse->aColCache[i] = pParse->aColCache[pParse->nColCache];
  }
}


/*
** Record in the column cache that a particular column from a
** particular table is stored in a particular register.
*/
void sqlite3ExprCacheStore(Parse *pParse, int iTab, int iCol, int iReg){
  int i;
  int minLru;
  int idxLru;
  struct yColCache *p;

  /* Unless an error has occurred, register numbers are always positive. */
  assert( iReg>0 || pParse->nErr || pParse->db->mallocFailed );
  assert( iCol>=-1 && iCol<32768 );  /* Finite column numbers */

  /* The SQLITE_ColumnCache flag disables the column cache.  This is used
  ** for testing only - to verify that SQLite always gets the same answer
  ** with and without the column cache.
  */
  if( OptimizationDisabled(pParse->db, SQLITE_ColumnCache) ) return;

  /* First replace any existing entry.
  **
  ** Actually, the way the column cache is currently used, we are guaranteed
  ** that the object will never already be in cache.  Verify this guarantee.
  */
#ifndef NDEBUG
  for(i=0, p=pParse->aColCache; i<pParse->nColCache; i++, p++){
    assert( p->iTable!=iTab || p->iColumn!=iCol );
  }
#endif

  /* If the cache is already full, delete the least recently used entry */
  if( pParse->nColCache>=SQLITE_N_COLCACHE ){
    minLru = 0x7fffffff;
    idxLru = -1;
    for(i=0, p=pParse->aColCache; i<SQLITE_N_COLCACHE; i++, p++){
      if( p->lru<minLru ){
        idxLru = i;
        minLru = p->lru;
      }
    }
    p = &pParse->aColCache[idxLru];
  }else{
    p = &pParse->aColCache[pParse->nColCache++];
  }

  /* Add the new entry to the end of the cache */
  p->iLevel = pParse->iCacheLevel;
  p->iTable = iTab;
  p->iColumn = iCol;
  p->iReg = iReg;
  p->tempReg = 0;
  p->lru = pParse->iCacheCnt++;
}

/*
** Indicate that registers between iReg..iReg+nReg-1 are being overwritten.
** Purge the range of registers from the column cache.
*/
void sqlite3ExprCacheRemove(Parse *pParse, int iReg, int nReg){
  int i = 0;
  while( i<pParse->nColCache ){
    struct yColCache *p = &pParse->aColCache[i];
    if( p->iReg >= iReg && p->iReg < iReg+nReg ){
      cacheEntryClear(pParse, i);
    }else{
      i++;
    }
  }
}

/*
** Remember the current column cache context.  Any new entries added
** added to the column cache after this call are removed when the
** corresponding pop occurs.
*/
void sqlite3ExprCachePush(Parse *pParse){
  pParse->iCacheLevel++;
#ifdef SQLITE_DEBUG
  if( pParse->db->flags & SQLITE_VdbeAddopTrace ){
    printf("PUSH to %d\n", pParse->iCacheLevel);
  }
#endif
}

/*
** Remove from the column cache any entries that were added since the
** the previous sqlite3ExprCachePush operation.  In other words, restore
** the cache to the state it was in prior the most recent Push.
*/
void sqlite3ExprCachePop(Parse *pParse){
  int i = 0;
  assert( pParse->iCacheLevel>=1 );
  pParse->iCacheLevel--;
#ifdef SQLITE_DEBUG
  if( pParse->db->flags & SQLITE_VdbeAddopTrace ){
    printf("POP  to %d\n", pParse->iCacheLevel);
  }
#endif
  while( i<pParse->nColCache ){
    if( pParse->aColCache[i].iLevel>pParse->iCacheLevel ){
      cacheEntryClear(pParse, i);
    }else{
      i++;
    }
  }
}

/*
** When a cached column is reused, make sure that its register is
** no longer available as a temp register.  ticket #3879:  that same
** register might be in the cache in multiple places, so be sure to
** get them all.
*/
static void sqlite3ExprCachePinRegister(Parse *pParse, int iReg){
  int i;
  struct yColCache *p;
  for(i=0, p=pParse->aColCache; i<pParse->nColCache; i++, p++){
    if( p->iReg==iReg ){
      p->tempReg = 0;
    }
  }
}

/* Generate code that will load into register regOut a value that is
** appropriate for the iIdxCol-th column of index pIdx.
*/
void sqlite3ExprCodeLoadIndexColumn(
  Parse *pParse,  /* The parsing context */
  Index *pIdx,    /* The index whose column is to be loaded */
  int iTabCur,    /* Cursor pointing to a table row */
  int iIdxCol,    /* The column of the index to be loaded */
  int regOut      /* Store the index column value in this register */
){
  i16 iTabCol = pIdx->aiColumn[iIdxCol];
  if( iTabCol==XN_EXPR ){
    assert( pIdx->aColExpr );
    assert( pIdx->aColExpr->nExpr>iIdxCol );
    pParse->iSelfTab = iTabCur + 1;
    sqlite3ExprCodeCopy(pParse, pIdx->aColExpr->a[iIdxCol].pExpr, regOut);
    pParse->iSelfTab = 0;
  }else{
    sqlite3ExprCodeGetColumnOfTable(pParse->pVdbe, pIdx->pTable, iTabCur,
                                    iTabCol, regOut);
  }
}

/*
** Generate code to extract the value of the iCol-th column of a table.
*/
void sqlite3ExprCodeGetColumnOfTable(
  Vdbe *v,        /* The VDBE under construction */
  Table *pTab,    /* The table containing the value */
  int iTabCur,    /* The table cursor.  Or the PK cursor for WITHOUT ROWID */
  int iCol,       /* Index of the column to extract */
  int regOut      /* Extract the value into this register */
){
  if( pTab==0 ){
    sqlite3VdbeAddOp3(v, OP_Column, iTabCur, iCol, regOut);
    return;
  }
  if( iCol<0 || iCol==pTab->iPKey ){
    sqlite3VdbeAddOp2(v, OP_Rowid, iTabCur, regOut);
  }else{
    int op = IsVirtual(pTab) ? OP_VColumn : OP_Column;
    int x = iCol;
    if( !HasRowid(pTab) && !IsVirtual(pTab) ){
      x = sqlite3ColumnOfIndex(sqlite3PrimaryKeyIndex(pTab), iCol);
    }
    sqlite3VdbeAddOp3(v, op, iTabCur, x, regOut);
  }
  if( iCol>=0 ){
    sqlite3ColumnDefault(v, pTab, iCol, regOut);
  }
}

/*
** Generate code that will extract the iColumn-th column from
** table pTab and store the column value in a register. 
**
** An effort is made to store the column value in register iReg.  This
** is not garanteeed for GetColumn() - the result can be stored in
** any register.  But the result is guaranteed to land in register iReg
** for GetColumnToReg().
**
** There must be an open cursor to pTab in iTable when this routine
** is called.  If iColumn<0 then code is generated that extracts the rowid.
*/
int sqlite3ExprCodeGetColumn(
  Parse *pParse,   /* Parsing and code generating context */
  Table *pTab,     /* Description of the table we are reading from */
  int iColumn,     /* Index of the table column */
  int iTable,      /* The cursor pointing to the table */
  int iReg,        /* Store results here */
  u8 p5            /* P5 value for OP_Column + FLAGS */
){
  Vdbe *v = pParse->pVdbe;
  int i;
  struct yColCache *p;

  for(i=0, p=pParse->aColCache; i<pParse->nColCache; i++, p++){
    if( p->iTable==iTable && p->iColumn==iColumn ){
      p->lru = pParse->iCacheCnt++;
      sqlite3ExprCachePinRegister(pParse, p->iReg);
      return p->iReg;
    }
  }  
  assert( v!=0 );
  sqlite3ExprCodeGetColumnOfTable(v, pTab, iTable, iColumn, iReg);
  if( p5 ){
    sqlite3VdbeChangeP5(v, p5);
  }else{   
    sqlite3ExprCacheStore(pParse, iTable, iColumn, iReg);
  }
  return iReg;
}
void sqlite3ExprCodeGetColumnToReg(
  Parse *pParse,   /* Parsing and code generating context */
  Table *pTab,     /* Description of the table we are reading from */
  int iColumn,     /* Index of the table column */
  int iTable,      /* The cursor pointing to the table */
  int iReg         /* Store results here */
){
  int r1 = sqlite3ExprCodeGetColumn(pParse, pTab, iColumn, iTable, iReg, 0);
  if( r1!=iReg ) sqlite3VdbeAddOp2(pParse->pVdbe, OP_SCopy, r1, iReg);
}


/*
** Clear all column cache entries.
*/
void sqlite3ExprCacheClear(Parse *pParse){
  int i;

#ifdef SQLITE_DEBUG
  if( pParse->db->flags & SQLITE_VdbeAddopTrace ){
    printf("CLEAR\n");
  }
#endif
  for(i=0; i<pParse->nColCache; i++){
    if( pParse->aColCache[i].tempReg
     && pParse->nTempReg<ArraySize(pParse->aTempReg)
    ){
       pParse->aTempReg[pParse->nTempReg++] = pParse->aColCache[i].iReg;
    }
  }
  pParse->nColCache = 0;
}

/*
** Record the fact that an affinity change has occurred on iCount
** registers starting with iStart.
*/
void sqlite3ExprCacheAffinityChange(Parse *pParse, int iStart, int iCount){
  sqlite3ExprCacheRemove(pParse, iStart, iCount);
}

/*
** Generate code to move content from registers iFrom...iFrom+nReg-1
** over to iTo..iTo+nReg-1. Keep the column cache up-to-date.
*/
void sqlite3ExprCodeMove(Parse *pParse, int iFrom, int iTo, int nReg){
  assert( iFrom>=iTo+nReg || iFrom+nReg<=iTo );
  sqlite3VdbeAddOp3(pParse->pVdbe, OP_Move, iFrom, iTo, nReg);
  sqlite3ExprCacheRemove(pParse, iFrom, nReg);
}

#if defined(SQLITE_DEBUG) || defined(SQLITE_COVERAGE_TEST)
/*
** Return true if any register in the range iFrom..iTo (inclusive)
** is used as part of the column cache.
**
** This routine is used within assert() and testcase() macros only
** and does not appear in a normal build.
*/
static int usedAsColumnCache(Parse *pParse, int iFrom, int iTo){
  int i;
  struct yColCache *p;
  for(i=0, p=pParse->aColCache; i<pParse->nColCache; i++, p++){
    int r = p->iReg;
    if( r>=iFrom && r<=iTo ) return 1;    /*NO_TEST*/
  }
  return 0;
}
#endif /* SQLITE_DEBUG || SQLITE_COVERAGE_TEST */


/*
** Convert a scalar expression node to a TK_REGISTER referencing
** register iReg.  The caller must ensure that iReg already contains
** the correct value for the expression.
*/
static void exprToRegister(Expr *p, int iReg){
  p->op2 = p->op;
  p->op = TK_REGISTER;
  p->iTable = iReg;
  ExprClearProperty(p, EP_Skip);
}

/*
** Evaluate an expression (either a vector or a scalar expression) and store
** the result in continguous temporary registers.  Return the index of
** the first register used to store the result.
**
** If the returned result register is a temporary scalar, then also write
** that register number into *piFreeable.  If the returned result register
** is not a temporary or if the expression is a vector set *piFreeable
** to 0.
*/
static int exprCodeVector(Parse *pParse, Expr *p, int *piFreeable){
  int iResult;
  int nResult = sqlite3ExprVectorSize(p);
  if( nResult==1 ){
    iResult = sqlite3ExprCodeTemp(pParse, p, piFreeable);
  }else{
    *piFreeable = 0;
    if( p->op==TK_SELECT ){
#if SQLITE_OMIT_SUBQUERY
      iResult = 0;
#else
      iResult = sqlite3CodeSubselect(pParse, p, 0, 0);
#endif
    }else{
      int i;
      iResult = pParse->nMem+1;
      pParse->nMem += nResult;
      for(i=0; i<nResult; i++){
        sqlite3ExprCodeFactorable(pParse, p->x.pList->a[i].pExpr, i+iResult);
      }
    }
  }
  return iResult;
}


/*
** Generate code into the current Vdbe to evaluate the given
** expression.  Attempt to store the results in register "target".
** Return the register where results are stored.
**
** With this routine, there is no guarantee that results will
** be stored in target.  The result might be stored in some other
** register if it is convenient to do so.  The calling function
** must check the return code and move the results to the desired
** register.
*/
int sqlite3ExprCodeTarget(Parse *pParse, Expr *pExpr, int target){
  Vdbe *v = pParse->pVdbe;  /* The VM under construction */
  int op;                   /* The opcode being coded */
  int inReg = target;       /* Results stored in register inReg */
  int regFree1 = 0;         /* If non-zero free this temporary register */
  int regFree2 = 0;         /* If non-zero free this temporary register */
  int r1, r2;               /* Various register numbers */
  Expr tempX;               /* Temporary expression node */
  int p5 = 0;

  assert( target>0 && target<=pParse->nMem );
  if( v==0 ){
    assert( pParse->db->mallocFailed );
    return 0;
  }

  if( pExpr==0 ){
    op = TK_NULL;
  }else{
    op = pExpr->op;
  }
  switch( op ){
    case TK_AGG_COLUMN: {
      AggInfo *pAggInfo = pExpr->pAggInfo;
      struct AggInfo_col *pCol = &pAggInfo->aCol[pExpr->iAgg];
      if( !pAggInfo->directMode ){
        assert( pCol->iMem>0 );
        return pCol->iMem;
      }else if( pAggInfo->useSortingIdx ){
        sqlite3VdbeAddOp3(v, OP_Column, pAggInfo->sortingIdxPTab,
                              pCol->iSorterColumn, target);
        return target;
      }
      /* Otherwise, fall thru into the TK_COLUMN case */
    }
    case TK_COLUMN: {
      int iTab = pExpr->iTable;
      if( iTab<0 ){
        if( pParse->iSelfTab<0 ){
          /* Generating CHECK constraints or inserting into partial index */
          return pExpr->iColumn - pParse->iSelfTab;
        }else{
          /* Coding an expression that is part of an index where column names
          ** in the index refer to the table to which the index belongs */
          iTab = pParse->iSelfTab - 1;
        }
      }
      return sqlite3ExprCodeGetColumn(pParse, pExpr->pTab,
                               pExpr->iColumn, iTab, target,
                               pExpr->op2);
    }
    case TK_INTEGER: {
      codeInteger(pParse, pExpr, 0, target);
      return target;
    }
#ifndef SQLITE_OMIT_FLOATING_POINT
    case TK_FLOAT: {
      assert( !ExprHasProperty(pExpr, EP_IntValue) );
      codeReal(v, pExpr->u.zToken, 0, target);
      return target;
    }
#endif
    case TK_STRING: {
      assert( !ExprHasProperty(pExpr, EP_IntValue) );
      sqlite3VdbeLoadString(v, target, pExpr->u.zToken);
      return target;
    }
    case TK_NULL: {
      sqlite3VdbeAddOp2(v, OP_Null, 0, target);
      return target;
    }
#ifndef SQLITE_OMIT_BLOB_LITERAL
    case TK_BLOB: {
      int n;
      const char *z;
      char *zBlob;
      assert( !ExprHasProperty(pExpr, EP_IntValue) );
      assert( pExpr->u.zToken[0]=='x' || pExpr->u.zToken[0]=='X' );
      assert( pExpr->u.zToken[1]=='\'' );
      z = &pExpr->u.zToken[2];
      n = sqlite3Strlen30(z) - 1;
      assert( z[n]=='\'' );
      zBlob = sqlite3HexToBlob(sqlite3VdbeDb(v), z, n);
      sqlite3VdbeAddOp4(v, OP_Blob, n/2, target, 0, zBlob, P4_DYNAMIC);
      return target;
    }
#endif
    case TK_VARIABLE: {
      assert( !ExprHasProperty(pExpr, EP_IntValue) );
      assert( pExpr->u.zToken!=0 );
      assert( pExpr->u.zToken[0]!=0 );
      sqlite3VdbeAddOp2(v, OP_Variable, pExpr->iColumn, target);
      if( pExpr->u.zToken[1]!=0 ){
        const char *z = sqlite3VListNumToName(pParse->pVList, pExpr->iColumn);
        assert( pExpr->u.zToken[0]=='?' || strcmp(pExpr->u.zToken, z)==0 );
        pParse->pVList[0] = 0; /* Indicate VList may no longer be enlarged */
        sqlite3VdbeAppendP4(v, (char*)z, P4_STATIC);
      }
      return target;
    }
    case TK_REGISTER: {
      return pExpr->iTable;
    }
#ifndef SQLITE_OMIT_CAST
    case TK_CAST: {
      /* Expressions of the form:   CAST(pLeft AS token) */
      inReg = sqlite3ExprCodeTarget(pParse, pExpr->pLeft, target);
      if( inReg!=target ){
        sqlite3VdbeAddOp2(v, OP_SCopy, inReg, target);
        inReg = target;
      }
      sqlite3VdbeAddOp2(v, OP_Cast, target,
                        sqlite3AffinityType(pExpr->u.zToken, 0));
      testcase( usedAsColumnCache(pParse, inReg, inReg) );
      sqlite3ExprCacheAffinityChange(pParse, inReg, 1);
      return inReg;
    }
#endif /* SQLITE_OMIT_CAST */
    case TK_IS:
    case TK_ISNOT:
      op = (op==TK_IS) ? TK_EQ : TK_NE;
      p5 = SQLITE_NULLEQ;
      /* fall-through */
    case TK_LT:
    case TK_LE:
    case TK_GT:
    case TK_GE:
    case TK_NE:
    case TK_EQ: {
      Expr *pLeft = pExpr->pLeft;
      if( sqlite3ExprIsVector(pLeft) ){
        codeVectorCompare(pParse, pExpr, target, op, p5);
      }else{
        r1 = sqlite3ExprCodeTemp(pParse, pLeft, &regFree1);
        r2 = sqlite3ExprCodeTemp(pParse, pExpr->pRight, &regFree2);
        codeCompare(pParse, pLeft, pExpr->pRight, op,
            r1, r2, inReg, SQLITE_STOREP2 | p5);
        assert(TK_LT==OP_Lt); testcase(op==OP_Lt); VdbeCoverageIf(v,op==OP_Lt);
        assert(TK_LE==OP_Le); testcase(op==OP_Le); VdbeCoverageIf(v,op==OP_Le);
        assert(TK_GT==OP_Gt); testcase(op==OP_Gt); VdbeCoverageIf(v,op==OP_Gt);
        assert(TK_GE==OP_Ge); testcase(op==OP_Ge); VdbeCoverageIf(v,op==OP_Ge);
        assert(TK_EQ==OP_Eq); testcase(op==OP_Eq); VdbeCoverageIf(v,op==OP_Eq);
        assert(TK_NE==OP_Ne); testcase(op==OP_Ne); VdbeCoverageIf(v,op==OP_Ne);
        testcase( regFree1==0 );
        testcase( regFree2==0 );
      }
      break;
    }
    case TK_AND:
    case TK_OR:
    case TK_PLUS:
    case TK_STAR:
    case TK_MINUS:
    case TK_REM:
    case TK_BITAND:
    case TK_BITOR:
    case TK_SLASH:
    case TK_LSHIFT:
    case TK_RSHIFT: 
    case TK_CONCAT: {
      assert( TK_AND==OP_And );            testcase( op==TK_AND );
      assert( TK_OR==OP_Or );              testcase( op==TK_OR );
      assert( TK_PLUS==OP_Add );           testcase( op==TK_PLUS );
      assert( TK_MINUS==OP_Subtract );     testcase( op==TK_MINUS );
      assert( TK_REM==OP_Remainder );      testcase( op==TK_REM );
      assert( TK_BITAND==OP_BitAnd );      testcase( op==TK_BITAND );
      assert( TK_BITOR==OP_BitOr );        testcase( op==TK_BITOR );
      assert( TK_SLASH==OP_Divide );       testcase( op==TK_SLASH );
      assert( TK_LSHIFT==OP_ShiftLeft );   testcase( op==TK_LSHIFT );
      assert( TK_RSHIFT==OP_ShiftRight );  testcase( op==TK_RSHIFT );
      assert( TK_CONCAT==OP_Concat );      testcase( op==TK_CONCAT );
      r1 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree1);
      r2 = sqlite3ExprCodeTemp(pParse, pExpr->pRight, &regFree2);
      sqlite3VdbeAddOp3(v, op, r2, r1, target);
      testcase( regFree1==0 );
      testcase( regFree2==0 );
      break;
    }
    case TK_UMINUS: {
      Expr *pLeft = pExpr->pLeft;
      assert( pLeft );
      if( pLeft->op==TK_INTEGER ){
        codeInteger(pParse, pLeft, 1, target);
        return target;
#ifndef SQLITE_OMIT_FLOATING_POINT
      }else if( pLeft->op==TK_FLOAT ){
        assert( !ExprHasProperty(pExpr, EP_IntValue) );
        codeReal(v, pLeft->u.zToken, 1, target);
        return target;
#endif
      }else{
        tempX.op = TK_INTEGER;
        tempX.flags = EP_IntValue|EP_TokenOnly;
        tempX.u.iValue = 0;
        r1 = sqlite3ExprCodeTemp(pParse, &tempX, &regFree1);
        r2 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree2);
        sqlite3VdbeAddOp3(v, OP_Subtract, r2, r1, target);
        testcase( regFree2==0 );
      }
      break;
    }
    case TK_BITNOT:
    case TK_NOT: {
      assert( TK_BITNOT==OP_BitNot );   testcase( op==TK_BITNOT );
      assert( TK_NOT==OP_Not );         testcase( op==TK_NOT );
      r1 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree1);
      testcase( regFree1==0 );
      sqlite3VdbeAddOp2(v, op, r1, inReg);
      break;
    }
    case TK_ISNULL:
    case TK_NOTNULL: {
      int addr;
      assert( TK_ISNULL==OP_IsNull );   testcase( op==TK_ISNULL );
      assert( TK_NOTNULL==OP_NotNull ); testcase( op==TK_NOTNULL );
      sqlite3VdbeAddOp2(v, OP_Integer, 1, target);
      r1 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree1);
      testcase( regFree1==0 );
      addr = sqlite3VdbeAddOp1(v, op, r1);
      VdbeCoverageIf(v, op==TK_ISNULL);
      VdbeCoverageIf(v, op==TK_NOTNULL);
      sqlite3VdbeAddOp2(v, OP_Integer, 0, target);
      sqlite3VdbeJumpHere(v, addr);
      break;
    }
    case TK_AGG_FUNCTION: {
      AggInfo *pInfo = pExpr->pAggInfo;
      if( pInfo==0 ){
        assert( !ExprHasProperty(pExpr, EP_IntValue) );
        sqlite3ErrorMsg(pParse, "misuse of aggregate: %s()", pExpr->u.zToken);
      }else{
        return pInfo->aFunc[pExpr->iAgg].iMem;
      }
      break;
    }
    case TK_FUNCTION: {
      ExprList *pFarg;       /* List of function arguments */
      int nFarg;             /* Number of function arguments */
      FuncDef *pDef;         /* The function definition object */
      const char *zId;       /* The function name */
      u32 constMask = 0;     /* Mask of function arguments that are constant */
      int i;                 /* Loop counter */
      sqlite3 *db = pParse->db;  /* The database connection */
      u8 enc = ENC(db);      /* The text encoding used by this database */
      CollSeq *pColl = 0;    /* A collating sequence */

      if( ConstFactorOk(pParse) && sqlite3ExprIsConstantNotJoin(pExpr) ){
        /* SQL functions can be expensive. So try to move constant functions
        ** out of the inner loop, even if that means an extra OP_Copy. */
        return sqlite3ExprCodeAtInit(pParse, pExpr, -1);
      }
      assert( !ExprHasProperty(pExpr, EP_xIsSelect) );
      if( ExprHasProperty(pExpr, EP_TokenOnly) ){
        pFarg = 0;
      }else{
        pFarg = pExpr->x.pList;
      }
      nFarg = pFarg ? pFarg->nExpr : 0;
      assert( !ExprHasProperty(pExpr, EP_IntValue) );
      zId = pExpr->u.zToken;
      pDef = sqlite3FindFunction(db, zId, nFarg, enc, 0);
#ifdef SQLITE_ENABLE_UNKNOWN_SQL_FUNCTION
      if( pDef==0 && pParse->explain ){
        pDef = sqlite3FindFunction(db, "unknown", nFarg, enc, 0);
      }
#endif
      if( pDef==0 || pDef->xFinalize!=0 ){
        sqlite3ErrorMsg(pParse, "unknown function: %s()", zId);
        break;
      }

      /* Attempt a direct implementation of the built-in COALESCE() and
      ** IFNULL() functions.  This avoids unnecessary evaluation of
      ** arguments past the first non-NULL argument.
      */
      if( pDef->funcFlags & SQLITE_FUNC_COALESCE ){
        int endCoalesce = sqlite3VdbeMakeLabel(v);
        assert( nFarg>=2 );
        sqlite3ExprCode(pParse, pFarg->a[0].pExpr, target);
        for(i=1; i<nFarg; i++){
          sqlite3VdbeAddOp2(v, OP_NotNull, target, endCoalesce);
          VdbeCoverage(v);
          sqlite3ExprCacheRemove(pParse, target, 1);
          sqlite3ExprCachePush(pParse);
          sqlite3ExprCode(pParse, pFarg->a[i].pExpr, target);
          sqlite3ExprCachePop(pParse);
        }
        sqlite3VdbeResolveLabel(v, endCoalesce);
        break;
      }

      /* The UNLIKELY() function is a no-op.  The result is the value
      ** of the first argument.
      */
      if( pDef->funcFlags & SQLITE_FUNC_UNLIKELY ){
        assert( nFarg>=1 );
        return sqlite3ExprCodeTarget(pParse, pFarg->a[0].pExpr, target);
      }

#ifdef SQLITE_DEBUG
      /* The AFFINITY() function evaluates to a string that describes
      ** the type affinity of the argument.  This is used for testing of
      ** the SQLite type logic.
      */
      if( pDef->funcFlags & SQLITE_FUNC_AFFINITY ){
        const char *azAff[] = { "blob", "text", "numeric", "integer", "real" };
        char aff;
        assert( nFarg==1 );
        aff = sqlite3ExprAffinity(pFarg->a[0].pExpr);
        sqlite3VdbeLoadString(v, target, 
                              aff ? azAff[aff-SQLITE_AFF_BLOB] : "none");
        return target;
      }
#endif

      for(i=0; i<nFarg; i++){
        if( i<32 && sqlite3ExprIsConstant(pFarg->a[i].pExpr) ){
          testcase( i==31 );
          constMask |= MASKBIT32(i);
        }
        if( (pDef->funcFlags & SQLITE_FUNC_NEEDCOLL)!=0 && !pColl ){
          pColl = sqlite3ExprCollSeq(pParse, pFarg->a[i].pExpr);
        }
      }
      if( pFarg ){
        if( constMask ){
          r1 = pParse->nMem+1;
          pParse->nMem += nFarg;
        }else{
          r1 = sqlite3GetTempRange(pParse, nFarg);
        }

        /* For length() and typeof() functions with a column argument,
        ** set the P5 parameter to the OP_Column opcode to OPFLAG_LENGTHARG
        ** or OPFLAG_TYPEOFARG respectively, to avoid unnecessary data
        ** loading.
        */
        if( (pDef->funcFlags & (SQLITE_FUNC_LENGTH|SQLITE_FUNC_TYPEOF))!=0 ){
          u8 exprOp;
          assert( nFarg==1 );
          assert( pFarg->a[0].pExpr!=0 );
          exprOp = pFarg->a[0].pExpr->op;
          if( exprOp==TK_COLUMN || exprOp==TK_AGG_COLUMN ){
            assert( SQLITE_FUNC_LENGTH==OPFLAG_LENGTHARG );
            assert( SQLITE_FUNC_TYPEOF==OPFLAG_TYPEOFARG );
            testcase( pDef->funcFlags & OPFLAG_LENGTHARG );
            pFarg->a[0].pExpr->op2 = 
                  pDef->funcFlags & (OPFLAG_LENGTHARG|OPFLAG_TYPEOFARG);
          }
        }

        sqlite3ExprCachePush(pParse);     /* Ticket 2ea2425d34be */
        sqlite3ExprCodeExprList(pParse, pFarg, r1, 0,
                                SQLITE_ECEL_DUP|SQLITE_ECEL_FACTOR);
        sqlite3ExprCachePop(pParse);      /* Ticket 2ea2425d34be */
      }else{
        r1 = 0;
      }
#ifndef SQLITE_OMIT_VIRTUALTABLE
      /* Possibly overload the function if the first argument is
      ** a virtual table column.
      **
      ** For infix functions (LIKE, GLOB, REGEXP, and MATCH) use the
      ** second argument, not the first, as the argument to test to
      ** see if it is a column in a virtual table.  This is done because
      ** the left operand of infix functions (the operand we want to
      ** control overloading) ends up as the second argument to the
      ** function.  The expression "A glob B" is equivalent to 
      ** "glob(B,A).  We want to use the A in "A glob B" to test
      ** for function overloading.  But we use the B term in "glob(B,A)".
      */
      if( nFarg>=2 && (pExpr->flags & EP_InfixFunc) ){
        pDef = sqlite3VtabOverloadFunction(db, pDef, nFarg, pFarg->a[1].pExpr);
      }else if( nFarg>0 ){
        pDef = sqlite3VtabOverloadFunction(db, pDef, nFarg, pFarg->a[0].pExpr);
      }
#endif
      if( pDef->funcFlags & SQLITE_FUNC_NEEDCOLL ){
        if( !pColl ) pColl = db->pDfltColl; 
        sqlite3VdbeAddOp4(v, OP_CollSeq, 0, 0, 0, (char *)pColl, P4_COLLSEQ);
      }
      sqlite3VdbeAddOp4(v, pParse->iSelfTab ? OP_PureFunc0 : OP_Function0,
                        constMask, r1, target, (char*)pDef, P4_FUNCDEF);
      sqlite3VdbeChangeP5(v, (u8)nFarg);
      if( nFarg && constMask==0 ){
        sqlite3ReleaseTempRange(pParse, r1, nFarg);
      }
      return target;
    }
#ifndef SQLITE_OMIT_SUBQUERY
    case TK_EXISTS:
    case TK_SELECT: {
      int nCol;
      testcase( op==TK_EXISTS );
      testcase( op==TK_SELECT );
      if( op==TK_SELECT && (nCol = pExpr->x.pSelect->pEList->nExpr)!=1 ){
        sqlite3SubselectError(pParse, nCol, 1);
      }else{
        return sqlite3CodeSubselect(pParse, pExpr, 0, 0);
      }
      break;
    }
    case TK_SELECT_COLUMN: {
      int n;
      if( pExpr->pLeft->iTable==0 ){
        pExpr->pLeft->iTable = sqlite3CodeSubselect(pParse, pExpr->pLeft, 0, 0);
      }
      assert( pExpr->iTable==0 || pExpr->pLeft->op==TK_SELECT );
      if( pExpr->iTable
       && pExpr->iTable!=(n = sqlite3ExprVectorSize(pExpr->pLeft)) 
      ){
        sqlite3ErrorMsg(pParse, "%d columns assigned %d values",
                                pExpr->iTable, n);
      }
      return pExpr->pLeft->iTable + pExpr->iColumn;
    }
    case TK_IN: {
      int destIfFalse = sqlite3VdbeMakeLabel(v);
      int destIfNull = sqlite3VdbeMakeLabel(v);
      sqlite3VdbeAddOp2(v, OP_Null, 0, target);
      sqlite3ExprCodeIN(pParse, pExpr, destIfFalse, destIfNull);
      sqlite3VdbeAddOp2(v, OP_Integer, 1, target);
      sqlite3VdbeResolveLabel(v, destIfFalse);
      sqlite3VdbeAddOp2(v, OP_AddImm, target, 0);
      sqlite3VdbeResolveLabel(v, destIfNull);
      return target;
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
      exprCodeBetween(pParse, pExpr, target, 0, 0);
      return target;
    }
    case TK_SPAN:
    case TK_COLLATE: 
    case TK_UPLUS: {
      return sqlite3ExprCodeTarget(pParse, pExpr->pLeft, target);
    }

    case TK_TRIGGER: {
      /* If the opcode is TK_TRIGGER, then the expression is a reference
      ** to a column in the new.* or old.* pseudo-tables available to
      ** trigger programs. In this case Expr.iTable is set to 1 for the
      ** new.* pseudo-table, or 0 for the old.* pseudo-table. Expr.iColumn
      ** is set to the column of the pseudo-table to read, or to -1 to
      ** read the rowid field.
      **
      ** The expression is implemented using an OP_Param opcode. The p1
      ** parameter is set to 0 for an old.rowid reference, or to (i+1)
      ** to reference another column of the old.* pseudo-table, where 
      ** i is the index of the column. For a new.rowid reference, p1 is
      ** set to (n+1), where n is the number of columns in each pseudo-table.
      ** For a reference to any other column in the new.* pseudo-table, p1
      ** is set to (n+2+i), where n and i are as defined previously. For
      ** example, if the table on which triggers are being fired is
      ** declared as:
      **
      **   CREATE TABLE t1(a, b);
      **
      ** Then p1 is interpreted as follows:
      **
      **   p1==0   ->    old.rowid     p1==3   ->    new.rowid
      **   p1==1   ->    old.a         p1==4   ->    new.a
      **   p1==2   ->    old.b         p1==5   ->    new.b       
      */
      Table *pTab = pExpr->pTab;
      int p1 = pExpr->iTable * (pTab->nCol+1) + 1 + pExpr->iColumn;

      assert( pExpr->iTable==0 || pExpr->iTable==1 );
      assert( pExpr->iColumn>=-1 && pExpr->iColumn<pTab->nCol );
      assert( pTab->iPKey<0 || pExpr->iColumn!=pTab->iPKey );
      assert( p1>=0 && p1<(pTab->nCol*2+2) );

      sqlite3VdbeAddOp2(v, OP_Param, p1, target);
      VdbeComment((v, "%s.%s -> $%d",
        (pExpr->iTable ? "new" : "old"),
        (pExpr->iColumn<0 ? "rowid" : pExpr->pTab->aCol[pExpr->iColumn].zName),
        target
      ));

#ifndef SQLITE_OMIT_FLOATING_POINT
      /* If the column has REAL affinity, it may currently be stored as an
      ** integer. Use OP_RealAffinity to make sure it is really real.
      **
      ** EVIDENCE-OF: R-60985-57662 SQLite will convert the value back to
      ** floating point when extracting it from the record.  */
      if( pExpr->iColumn>=0 
       && pTab->aCol[pExpr->iColumn].affinity==SQLITE_AFF_REAL
      ){
        sqlite3VdbeAddOp1(v, OP_RealAffinity, target);
      }
#endif
      break;
    }

    case TK_VECTOR: {
      sqlite3ErrorMsg(pParse, "row value misused");
      break;
    }

    case TK_IF_NULL_ROW: {
      int addrINR;
      addrINR = sqlite3VdbeAddOp1(v, OP_IfNullRow, pExpr->iTable);
      sqlite3ExprCachePush(pParse);
      inReg = sqlite3ExprCodeTarget(pParse, pExpr->pLeft, target);
      sqlite3ExprCachePop(pParse);
      sqlite3VdbeJumpHere(v, addrINR);
      sqlite3VdbeChangeP3(v, addrINR, inReg);
      break;
    }

    /*
    ** Form A:
    **   CASE x WHEN e1 THEN r1 WHEN e2 THEN r2 ... WHEN eN THEN rN ELSE y END
    **
    ** Form B:
    **   CASE WHEN e1 THEN r1 WHEN e2 THEN r2 ... WHEN eN THEN rN ELSE y END
    **
    ** Form A is can be transformed into the equivalent form B as follows:
    **   CASE WHEN x=e1 THEN r1 WHEN x=e2 THEN r2 ...
    **        WHEN x=eN THEN rN ELSE y END
    **
    ** X (if it exists) is in pExpr->pLeft.
    ** Y is in the last element of pExpr->x.pList if pExpr->x.pList->nExpr is
    ** odd.  The Y is also optional.  If the number of elements in x.pList
    ** is even, then Y is omitted and the "otherwise" result is NULL.
    ** Ei is in pExpr->pList->a[i*2] and Ri is pExpr->pList->a[i*2+1].
    **
    ** The result of the expression is the Ri for the first matching Ei,
    ** or if there is no matching Ei, the ELSE term Y, or if there is
    ** no ELSE term, NULL.
    */
    default: assert( op==TK_CASE ); {
      int endLabel;                     /* GOTO label for end of CASE stmt */
      int nextCase;                     /* GOTO label for next WHEN clause */
      int nExpr;                        /* 2x number of WHEN terms */
      int i;                            /* Loop counter */
      ExprList *pEList;                 /* List of WHEN terms */
      struct ExprList_item *aListelem;  /* Array of WHEN terms */
      Expr opCompare;                   /* The X==Ei expression */
      Expr *pX;                         /* The X expression */
      Expr *pTest = 0;                  /* X==Ei (form A) or just Ei (form B) */
      VVA_ONLY( int iCacheLevel = pParse->iCacheLevel; )

      assert( !ExprHasProperty(pExpr, EP_xIsSelect) && pExpr->x.pList );
      assert(pExpr->x.pList->nExpr > 0);
      pEList = pExpr->x.pList;
      aListelem = pEList->a;
      nExpr = pEList->nExpr;
      endLabel = sqlite3VdbeMakeLabel(v);
      if( (pX = pExpr->pLeft)!=0 ){
        tempX = *pX;
        testcase( pX->op==TK_COLUMN );
        exprToRegister(&tempX, exprCodeVector(pParse, &tempX, &regFree1));
        testcase( regFree1==0 );
        memset(&opCompare, 0, sizeof(opCompare));
        opCompare.op = TK_EQ;
        opCompare.pLeft = &tempX;
        pTest = &opCompare;
        /* Ticket b351d95f9cd5ef17e9d9dbae18f5ca8611190001:
        ** The value in regFree1 might get SCopy-ed into the file result.
        ** So make sure that the regFree1 register is not reused for other
        ** purposes and possibly overwritten.  */
        regFree1 = 0;
      }
      for(i=0; i<nExpr-1; i=i+2){
        sqlite3ExprCachePush(pParse);
        if( pX ){
          assert( pTest!=0 );
          opCompare.pRight = aListelem[i].pExpr;
        }else{
          pTest = aListelem[i].pExpr;
        }
        nextCase = sqlite3VdbeMakeLabel(v);
        testcase( pTest->op==TK_COLUMN );
        sqlite3ExprIfFalse(pParse, pTest, nextCase, SQLITE_JUMPIFNULL);
        testcase( aListelem[i+1].pExpr->op==TK_COLUMN );
        sqlite3ExprCode(pParse, aListelem[i+1].pExpr, target);
        sqlite3VdbeGoto(v, endLabel);
        sqlite3ExprCachePop(pParse);
        sqlite3VdbeResolveLabel(v, nextCase);
      }
      if( (nExpr&1)!=0 ){
        sqlite3ExprCachePush(pParse);
        sqlite3ExprCode(pParse, pEList->a[nExpr-1].pExpr, target);
        sqlite3ExprCachePop(pParse);
      }else{
        sqlite3VdbeAddOp2(v, OP_Null, 0, target);
      }
      assert( pParse->db->mallocFailed || pParse->nErr>0 
           || pParse->iCacheLevel==iCacheLevel );
      sqlite3VdbeResolveLabel(v, endLabel);
      break;
    }
#ifndef SQLITE_OMIT_TRIGGER
    case TK_RAISE: {
      assert( pExpr->affinity==OE_Rollback 
           || pExpr->affinity==OE_Abort
           || pExpr->affinity==OE_Fail
           || pExpr->affinity==OE_Ignore
      );
      if( !pParse->pTriggerTab ){
        sqlite3ErrorMsg(pParse,
                       "RAISE() may only be used within a trigger-program");
        return 0;
      }
      if( pExpr->affinity==OE_Abort ){
        sqlite3MayAbort(pParse);
      }
      assert( !ExprHasProperty(pExpr, EP_IntValue) );
      if( pExpr->affinity==OE_Ignore ){
        sqlite3VdbeAddOp4(
            v, OP_Halt, SQLITE_OK, OE_Ignore, 0, pExpr->u.zToken,0);
        VdbeCoverage(v);
      }else{
        sqlite3HaltConstraint(pParse, SQLITE_CONSTRAINT_TRIGGER,
                              pExpr->affinity, pExpr->u.zToken, 0, 0);
      }

      break;
    }
#endif
  }
  sqlite3ReleaseTempReg(pParse, regFree1);
  sqlite3ReleaseTempReg(pParse, regFree2);
  return inReg;
}

/*
** Factor out the code of the given expression to initialization time.
**
** If regDest>=0 then the result is always stored in that register and the
** result is not reusable.  If regDest<0 then this routine is free to 
** store the value whereever it wants.  The register where the expression 
** is stored is returned.  When regDest<0, two identical expressions will
** code to the same register.
*/
int sqlite3ExprCodeAtInit(
  Parse *pParse,    /* Parsing context */
  Expr *pExpr,      /* The expression to code when the VDBE initializes */
  int regDest       /* Store the value in this register */
){
  ExprList *p;
  assert( ConstFactorOk(pParse) );
  p = pParse->pConstExpr;
  if( regDest<0 && p ){
    struct ExprList_item *pItem;
    int i;
    for(pItem=p->a, i=p->nExpr; i>0; pItem++, i--){
      if( pItem->reusable && sqlite3ExprCompare(0,pItem->pExpr,pExpr,-1)==0 ){
        return pItem->u.iConstExprReg;
      }
    }
  }
  pExpr = sqlite3ExprDup(pParse->db, pExpr, 0);
  p = sqlite3ExprListAppend(pParse, p, pExpr);
  if( p ){
     struct ExprList_item *pItem = &p->a[p->nExpr-1];
     pItem->reusable = regDest<0;
     if( regDest<0 ) regDest = ++pParse->nMem;
     pItem->u.iConstExprReg = regDest;
  }
  pParse->pConstExpr = p;
  return regDest;
}

/*
** Generate code to evaluate an expression and store the results
** into a register.  Return the register number where the results
** are stored.
**
** If the register is a temporary register that can be deallocated,
** then write its number into *pReg.  If the result register is not
** a temporary, then set *pReg to zero.
**
** If pExpr is a constant, then this routine might generate this
** code to fill the register in the initialization section of the
** VDBE program, in order to factor it out of the evaluation loop.
*/
int sqlite3ExprCodeTemp(Parse *pParse, Expr *pExpr, int *pReg){
  int r2;
  pExpr = sqlite3ExprSkipCollate(pExpr);
  if( ConstFactorOk(pParse)
   && pExpr->op!=TK_REGISTER
   && sqlite3ExprIsConstantNotJoin(pExpr)
  ){
    *pReg  = 0;
    r2 = sqlite3ExprCodeAtInit(pParse, pExpr, -1);
  }else{
    int r1 = sqlite3GetTempReg(pParse);
    r2 = sqlite3ExprCodeTarget(pParse, pExpr, r1);
    if( r2==r1 ){
      *pReg = r1;
    }else{
      sqlite3ReleaseTempReg(pParse, r1);
      *pReg = 0;
    }
  }
  return r2;
}

/*
** Generate code that will evaluate expression pExpr and store the
** results in register target.  The results are guaranteed to appear
** in register target.
*/
void sqlite3ExprCode(Parse *pParse, Expr *pExpr, int target){
  int inReg;

  assert( target>0 && target<=pParse->nMem );
  if( pExpr && pExpr->op==TK_REGISTER ){
    sqlite3VdbeAddOp2(pParse->pVdbe, OP_Copy, pExpr->iTable, target);
  }else{
    inReg = sqlite3ExprCodeTarget(pParse, pExpr, target);
    assert( pParse->pVdbe!=0 || pParse->db->mallocFailed );
    if( inReg!=target && pParse->pVdbe ){
      sqlite3VdbeAddOp2(pParse->pVdbe, OP_SCopy, inReg, target);
    }
  }
}

/*
** Make a transient copy of expression pExpr and then code it using
** sqlite3ExprCode().  This routine works just like sqlite3ExprCode()
** except that the input expression is guaranteed to be unchanged.
*/
void sqlite3ExprCodeCopy(Parse *pParse, Expr *pExpr, int target){
  sqlite3 *db = pParse->db;
  pExpr = sqlite3ExprDup(db, pExpr, 0);
  if( !db->mallocFailed ) sqlite3ExprCode(pParse, pExpr, target);
  sqlite3ExprDelete(db, pExpr);
}

/*
** Generate code that will evaluate expression pExpr and store the
** results in register target.  The results are guaranteed to appear
** in register target.  If the expression is constant, then this routine
** might choose to code the expression at initialization time.
*/
void sqlite3ExprCodeFactorable(Parse *pParse, Expr *pExpr, int target){
  if( pParse->okConstFactor && sqlite3ExprIsConstant(pExpr) ){
    sqlite3ExprCodeAtInit(pParse, pExpr, target);
  }else{
    sqlite3ExprCode(pParse, pExpr, target);
  }
}

/*
** Generate code that evaluates the given expression and puts the result
** in register target.
**
** Also make a copy of the expression results into another "cache" register
** and modify the expression so that the next time it is evaluated,
** the result is a copy of the cache register.
**
** This routine is used for expressions that are used multiple 
** times.  They are evaluated once and the results of the expression
** are reused.
*/
void sqlite3ExprCodeAndCache(Parse *pParse, Expr *pExpr, int target){
  Vdbe *v = pParse->pVdbe;
  int iMem;

  assert( target>0 );
  assert( pExpr->op!=TK_REGISTER );
  sqlite3ExprCode(pParse, pExpr, target);
  iMem = ++pParse->nMem;
  sqlite3VdbeAddOp2(v, OP_Copy, target, iMem);
  exprToRegister(pExpr, iMem);
}

/*
** Generate code that pushes the value of every element of the given
** expression list into a sequence of registers beginning at target.
**
** Return the number of elements evaluated.
**
** The SQLITE_ECEL_DUP flag prevents the arguments from being
** filled using OP_SCopy.  OP_Copy must be used instead.
**
** The SQLITE_ECEL_FACTOR argument allows constant arguments to be
** factored out into initialization code.
**
** The SQLITE_ECEL_REF flag means that expressions in the list with
** ExprList.a[].u.x.iOrderByCol>0 have already been evaluated and stored
** in registers at srcReg, and so the value can be copied from there.
*/
int sqlite3ExprCodeExprList(
  Parse *pParse,     /* Parsing context */
  ExprList *pList,   /* The expression list to be coded */
  int target,        /* Where to write results */
  int srcReg,        /* Source registers if SQLITE_ECEL_REF */
  u8 flags           /* SQLITE_ECEL_* flags */
){
  struct ExprList_item *pItem;
  int i, j, n;
  u8 copyOp = (flags & SQLITE_ECEL_DUP) ? OP_Copy : OP_SCopy;
  Vdbe *v = pParse->pVdbe;
  assert( pList!=0 );
  assert( target>0 );
  assert( pParse->pVdbe!=0 );  /* Never gets this far otherwise */
  n = pList->nExpr;
  if( !ConstFactorOk(pParse) ) flags &= ~SQLITE_ECEL_FACTOR;
  for(pItem=pList->a, i=0; i<n; i++, pItem++){
    Expr *pExpr = pItem->pExpr;
    if( (flags & SQLITE_ECEL_REF)!=0 && (j = pItem->u.x.iOrderByCol)>0 ){
      if( flags & SQLITE_ECEL_OMITREF ){
        i--;
        n--;
      }else{
        sqlite3VdbeAddOp2(v, copyOp, j+srcReg-1, target+i);
      }
    }else if( (flags & SQLITE_ECEL_FACTOR)!=0 && sqlite3ExprIsConstant(pExpr) ){
      sqlite3ExprCodeAtInit(pParse, pExpr, target+i);
    }else{
      int inReg = sqlite3ExprCodeTarget(pParse, pExpr, target+i);
      if( inReg!=target+i ){
        VdbeOp *pOp;
        if( copyOp==OP_Copy
         && (pOp=sqlite3VdbeGetOp(v, -1))->opcode==OP_Copy
         && pOp->p1+pOp->p3+1==inReg
         && pOp->p2+pOp->p3+1==target+i
        ){
          pOp->p3++;
        }else{
          sqlite3VdbeAddOp2(v, copyOp, inReg, target+i);
        }
      }
    }
  }
  return n;
}

/*
** Generate code for a BETWEEN operator.
**
**    x BETWEEN y AND z
**
** The above is equivalent to 
**
**    x>=y AND x<=z
**
** Code it as such, taking care to do the common subexpression
** elimination of x.
**
** The xJumpIf parameter determines details:
**
**    NULL:                   Store the boolean result in reg[dest]
**    sqlite3ExprIfTrue:      Jump to dest if true
**    sqlite3ExprIfFalse:     Jump to dest if false
**
** The jumpIfNull parameter is ignored if xJumpIf is NULL.
*/
static void exprCodeBetween(
  Parse *pParse,    /* Parsing and code generating context */
  Expr *pExpr,      /* The BETWEEN expression */
  int dest,         /* Jump destination or storage location */
  void (*xJump)(Parse*,Expr*,int,int), /* Action to take */
  int jumpIfNull    /* Take the jump if the BETWEEN is NULL */
){
 Expr exprAnd;     /* The AND operator in  x>=y AND x<=z  */
  Expr compLeft;    /* The  x>=y  term */
  Expr compRight;   /* The  x<=z  term */
  Expr exprX;       /* The  x  subexpression */
  int regFree1 = 0; /* Temporary use register */


  memset(&compLeft, 0, sizeof(Expr));
  memset(&compRight, 0, sizeof(Expr));
  memset(&exprAnd, 0, sizeof(Expr));

  assert( !ExprHasProperty(pExpr, EP_xIsSelect) );
  exprX = *pExpr->pLeft;
  exprAnd.op = TK_AND;
  exprAnd.pLeft = &compLeft;
  exprAnd.pRight = &compRight;
  compLeft.op = TK_GE;
  compLeft.pLeft = &exprX;
  compLeft.pRight = pExpr->x.pList->a[0].pExpr;
  compRight.op = TK_LE;
  compRight.pLeft = &exprX;
  compRight.pRight = pExpr->x.pList->a[1].pExpr;
  exprToRegister(&exprX, exprCodeVector(pParse, &exprX, &regFree1));
  if( xJump ){
    xJump(pParse, &exprAnd, dest, jumpIfNull);
  }else{
    /* Mark the expression is being from the ON or USING clause of a join
    ** so that the sqlite3ExprCodeTarget() routine will not attempt to move
    ** it into the Parse.pConstExpr list.  We should use a new bit for this,
    ** for clarity, but we are out of bits in the Expr.flags field so we
    ** have to reuse the EP_FromJoin bit.  Bummer. */
    exprX.flags |= EP_FromJoin;
    sqlite3ExprCodeTarget(pParse, &exprAnd, dest);
  }
  sqlite3ReleaseTempReg(pParse, regFree1);

  /* Ensure adequate test coverage */
  testcase( xJump==sqlite3ExprIfTrue  && jumpIfNull==0 && regFree1==0 );
  testcase( xJump==sqlite3ExprIfTrue  && jumpIfNull==0 && regFree1!=0 );
  testcase( xJump==sqlite3ExprIfTrue  && jumpIfNull!=0 && regFree1==0 );
  testcase( xJump==sqlite3ExprIfTrue  && jumpIfNull!=0 && regFree1!=0 );
  testcase( xJump==sqlite3ExprIfFalse && jumpIfNull==0 && regFree1==0 );
  testcase( xJump==sqlite3ExprIfFalse && jumpIfNull==0 && regFree1!=0 );
  testcase( xJump==sqlite3ExprIfFalse && jumpIfNull!=0 && regFree1==0 );
  testcase( xJump==sqlite3ExprIfFalse && jumpIfNull!=0 && regFree1!=0 );
  testcase( xJump==0 );
}

/*
** Generate code for a boolean expression such that a jump is made
** to the label "dest" if the expression is true but execution
** continues straight thru if the expression is false.
**
** If the expression evaluates to NULL (neither true nor false), then
** take the jump if the jumpIfNull flag is SQLITE_JUMPIFNULL.
**
** This code depends on the fact that certain token values (ex: TK_EQ)
** are the same as opcode values (ex: OP_Eq) that implement the corresponding
** operation.  Special comments in vdbe.c and the mkopcodeh.awk script in
** the make process cause these values to align.  Assert()s in the code
** below verify that the numbers are aligned correctly.
*/
void sqlite3ExprIfTrue(Parse *pParse, Expr *pExpr, int dest, int jumpIfNull){
  Vdbe *v = pParse->pVdbe;
  int op = 0;
  int regFree1 = 0;
  int regFree2 = 0;
  int r1, r2;

  assert( jumpIfNull==SQLITE_JUMPIFNULL || jumpIfNull==0 );
  if( NEVER(v==0) )     return;  /* Existence of VDBE checked by caller */
  if( NEVER(pExpr==0) ) return;  /* No way this can happen */
  op = pExpr->op;
  switch( op ){
    case TK_AND: {
      int d2 = sqlite3VdbeMakeLabel(v);
      testcase( jumpIfNull==0 );
      sqlite3ExprIfFalse(pParse, pExpr->pLeft, d2,jumpIfNull^SQLITE_JUMPIFNULL);
      sqlite3ExprCachePush(pParse);
      sqlite3ExprIfTrue(pParse, pExpr->pRight, dest, jumpIfNull);
      sqlite3VdbeResolveLabel(v, d2);
      sqlite3ExprCachePop(pParse);
      break;
    }
    case TK_OR: {
      testcase( jumpIfNull==0 );
      sqlite3ExprIfTrue(pParse, pExpr->pLeft, dest, jumpIfNull);
      sqlite3ExprCachePush(pParse);
      sqlite3ExprIfTrue(pParse, pExpr->pRight, dest, jumpIfNull);
      sqlite3ExprCachePop(pParse);
      break;
    }
    case TK_NOT: {
      testcase( jumpIfNull==0 );
      sqlite3ExprIfFalse(pParse, pExpr->pLeft, dest, jumpIfNull);
      break;
    }
    case TK_IS:
    case TK_ISNOT:
      testcase( op==TK_IS );
      testcase( op==TK_ISNOT );
      op = (op==TK_IS) ? TK_EQ : TK_NE;
      jumpIfNull = SQLITE_NULLEQ;
      /* Fall thru */
    case TK_LT:
    case TK_LE:
    case TK_GT:
    case TK_GE:
    case TK_NE:
    case TK_EQ: {
      if( sqlite3ExprIsVector(pExpr->pLeft) ) goto default_expr;
      testcase( jumpIfNull==0 );
      r1 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree1);
      r2 = sqlite3ExprCodeTemp(pParse, pExpr->pRight, &regFree2);
      codeCompare(pParse, pExpr->pLeft, pExpr->pRight, op,
                  r1, r2, dest, jumpIfNull);
      assert(TK_LT==OP_Lt); testcase(op==OP_Lt); VdbeCoverageIf(v,op==OP_Lt);
      assert(TK_LE==OP_Le); testcase(op==OP_Le); VdbeCoverageIf(v,op==OP_Le);
      assert(TK_GT==OP_Gt); testcase(op==OP_Gt); VdbeCoverageIf(v,op==OP_Gt);
      assert(TK_GE==OP_Ge); testcase(op==OP_Ge); VdbeCoverageIf(v,op==OP_Ge);
      assert(TK_EQ==OP_Eq); testcase(op==OP_Eq);
      VdbeCoverageIf(v, op==OP_Eq && jumpIfNull==SQLITE_NULLEQ);
      VdbeCoverageIf(v, op==OP_Eq && jumpIfNull!=SQLITE_NULLEQ);
      assert(TK_NE==OP_Ne); testcase(op==OP_Ne);
      VdbeCoverageIf(v, op==OP_Ne && jumpIfNull==SQLITE_NULLEQ);
      VdbeCoverageIf(v, op==OP_Ne && jumpIfNull!=SQLITE_NULLEQ);
      testcase( regFree1==0 );
      testcase( regFree2==0 );
      break;
    }
    case TK_ISNULL:
    case TK_NOTNULL: {
      assert( TK_ISNULL==OP_IsNull );   testcase( op==TK_ISNULL );
      assert( TK_NOTNULL==OP_NotNull ); testcase( op==TK_NOTNULL );
      r1 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree1);
      sqlite3VdbeAddOp2(v, op, r1, dest);
      VdbeCoverageIf(v, op==TK_ISNULL);
      VdbeCoverageIf(v, op==TK_NOTNULL);
      testcase( regFree1==0 );
      break;
    }
    case TK_BETWEEN: {
      testcase( jumpIfNull==0 );
      exprCodeBetween(pParse, pExpr, dest, sqlite3ExprIfTrue, jumpIfNull);
      break;
    }
#ifndef SQLITE_OMIT_SUBQUERY
    case TK_IN: {
      int destIfFalse = sqlite3VdbeMakeLabel(v);
      int destIfNull = jumpIfNull ? dest : destIfFalse;
      sqlite3ExprCodeIN(pParse, pExpr, destIfFalse, destIfNull);
      sqlite3VdbeGoto(v, dest);
      sqlite3VdbeResolveLabel(v, destIfFalse);
      break;
    }
#endif
    default: {
    default_expr:
      if( exprAlwaysTrue(pExpr) ){
        sqlite3VdbeGoto(v, dest);
      }else if( exprAlwaysFalse(pExpr) ){
        /* No-op */
      }else{
        r1 = sqlite3ExprCodeTemp(pParse, pExpr, &regFree1);
        sqlite3VdbeAddOp3(v, OP_If, r1, dest, jumpIfNull!=0);
        VdbeCoverage(v);
        testcase( regFree1==0 );
        testcase( jumpIfNull==0 );
      }
      break;
    }
  }
  sqlite3ReleaseTempReg(pParse, regFree1);
  sqlite3ReleaseTempReg(pParse, regFree2);  
}

/*
** Generate code for a boolean expression such that a jump is made
** to the label "dest" if the expression is false but execution
** continues straight thru if the expression is true.
**
** If the expression evaluates to NULL (neither true nor false) then
** jump if jumpIfNull is SQLITE_JUMPIFNULL or fall through if jumpIfNull
** is 0.
*/
void sqlite3ExprIfFalse(Parse *pParse, Expr *pExpr, int dest, int jumpIfNull){
  Vdbe *v = pParse->pVdbe;
  int op = 0;
  int regFree1 = 0;
  int regFree2 = 0;
  int r1, r2;

  assert( jumpIfNull==SQLITE_JUMPIFNULL || jumpIfNull==0 );
  if( NEVER(v==0) ) return; /* Existence of VDBE checked by caller */
  if( pExpr==0 )    return;

  /* The value of pExpr->op and op are related as follows:
  **
  **       pExpr->op            op
  **       ---------          ----------
  **       TK_ISNULL          OP_NotNull
  **       TK_NOTNULL         OP_IsNull
  **       TK_NE              OP_Eq
  **       TK_EQ              OP_Ne
  **       TK_GT              OP_Le
  **       TK_LE              OP_Gt
  **       TK_GE              OP_Lt
  **       TK_LT              OP_Ge
  **
  ** For other values of pExpr->op, op is undefined and unused.
  ** The value of TK_ and OP_ constants are arranged such that we
  ** can compute the mapping above using the following expression.
  ** Assert()s verify that the computation is correct.
  */
  op = ((pExpr->op+(TK_ISNULL&1))^1)-(TK_ISNULL&1);

  /* Verify correct alignment of TK_ and OP_ constants
  */
  assert( pExpr->op!=TK_ISNULL || op==OP_NotNull );
  assert( pExpr->op!=TK_NOTNULL || op==OP_IsNull );
  assert( pExpr->op!=TK_NE || op==OP_Eq );
  assert( pExpr->op!=TK_EQ || op==OP_Ne );
  assert( pExpr->op!=TK_LT || op==OP_Ge );
  assert( pExpr->op!=TK_LE || op==OP_Gt );
  assert( pExpr->op!=TK_GT || op==OP_Le );
  assert( pExpr->op!=TK_GE || op==OP_Lt );

  switch( pExpr->op ){
    case TK_AND: {
      testcase( jumpIfNull==0 );
      sqlite3ExprIfFalse(pParse, pExpr->pLeft, dest, jumpIfNull);
      sqlite3ExprCachePush(pParse);
      sqlite3ExprIfFalse(pParse, pExpr->pRight, dest, jumpIfNull);
      sqlite3ExprCachePop(pParse);
      break;
    }
    case TK_OR: {
      int d2 = sqlite3VdbeMakeLabel(v);
      testcase( jumpIfNull==0 );
      sqlite3ExprIfTrue(pParse, pExpr->pLeft, d2, jumpIfNull^SQLITE_JUMPIFNULL);
      sqlite3ExprCachePush(pParse);
      sqlite3ExprIfFalse(pParse, pExpr->pRight, dest, jumpIfNull);
      sqlite3VdbeResolveLabel(v, d2);
      sqlite3ExprCachePop(pParse);
      break;
    }
    case TK_NOT: {
      testcase( jumpIfNull==0 );
      sqlite3ExprIfTrue(pParse, pExpr->pLeft, dest, jumpIfNull);
      break;
    }
    case TK_IS:
    case TK_ISNOT:
      testcase( pExpr->op==TK_IS );
      testcase( pExpr->op==TK_ISNOT );
      op = (pExpr->op==TK_IS) ? TK_NE : TK_EQ;
      jumpIfNull = SQLITE_NULLEQ;
      /* Fall thru */
    case TK_LT:
    case TK_LE:
    case TK_GT:
    case TK_GE:
    case TK_NE:
    case TK_EQ: {
      if( sqlite3ExprIsVector(pExpr->pLeft) ) goto default_expr;
      testcase( jumpIfNull==0 );
      r1 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree1);
      r2 = sqlite3ExprCodeTemp(pParse, pExpr->pRight, &regFree2);
      codeCompare(pParse, pExpr->pLeft, pExpr->pRight, op,
                  r1, r2, dest, jumpIfNull);
      assert(TK_LT==OP_Lt); testcase(op==OP_Lt); VdbeCoverageIf(v,op==OP_Lt);
      assert(TK_LE==OP_Le); testcase(op==OP_Le); VdbeCoverageIf(v,op==OP_Le);
      assert(TK_GT==OP_Gt); testcase(op==OP_Gt); VdbeCoverageIf(v,op==OP_Gt);
      assert(TK_GE==OP_Ge); testcase(op==OP_Ge); VdbeCoverageIf(v,op==OP_Ge);
      assert(TK_EQ==OP_Eq); testcase(op==OP_Eq);
      VdbeCoverageIf(v, op==OP_Eq && jumpIfNull!=SQLITE_NULLEQ);
      VdbeCoverageIf(v, op==OP_Eq && jumpIfNull==SQLITE_NULLEQ);
      assert(TK_NE==OP_Ne); testcase(op==OP_Ne);
      VdbeCoverageIf(v, op==OP_Ne && jumpIfNull!=SQLITE_NULLEQ);
      VdbeCoverageIf(v, op==OP_Ne && jumpIfNull==SQLITE_NULLEQ);
      testcase( regFree1==0 );
      testcase( regFree2==0 );
      break;
    }
    case TK_ISNULL:
    case TK_NOTNULL: {
      r1 = sqlite3ExprCodeTemp(pParse, pExpr->pLeft, &regFree1);
      sqlite3VdbeAddOp2(v, op, r1, dest);
      testcase( op==TK_ISNULL );   VdbeCoverageIf(v, op==TK_ISNULL);
      testcase( op==TK_NOTNULL );  VdbeCoverageIf(v, op==TK_NOTNULL);
      testcase( regFree1==0 );
      break;
    }
    case TK_BETWEEN: {
      testcase( jumpIfNull==0 );
      exprCodeBetween(pParse, pExpr, dest, sqlite3ExprIfFalse, jumpIfNull);
      break;
    }
#ifndef SQLITE_OMIT_SUBQUERY
    case TK_IN: {
      if( jumpIfNull ){
        sqlite3ExprCodeIN(pParse, pExpr, dest, dest);
      }else{
        int destIfNull = sqlite3VdbeMakeLabel(v);
        sqlite3ExprCodeIN(pParse, pExpr, dest, destIfNull);
        sqlite3VdbeResolveLabel(v, destIfNull);
      }
      break;
    }
#endif
    default: {
    default_expr: 
      if( exprAlwaysFalse(pExpr) ){
        sqlite3VdbeGoto(v, dest);
      }else if( exprAlwaysTrue(pExpr) ){
        /* no-op */
      }else{
        r1 = sqlite3ExprCodeTemp(pParse, pExpr, &regFree1);
        sqlite3VdbeAddOp3(v, OP_IfNot, r1, dest, jumpIfNull!=0);
        VdbeCoverage(v);
        testcase( regFree1==0 );
        testcase( jumpIfNull==0 );
      }
      break;
    }
  }
  sqlite3ReleaseTempReg(pParse, regFree1);
  sqlite3ReleaseTempReg(pParse, regFree2);
}

/*
** Like sqlite3ExprIfFalse() except that a copy is made of pExpr before
** code generation, and that copy is deleted after code generation. This
** ensures that the original pExpr is unchanged.
*/
void sqlite3ExprIfFalseDup(Parse *pParse, Expr *pExpr, int dest,int jumpIfNull){
  sqlite3 *db = pParse->db;
  Expr *pCopy = sqlite3ExprDup(db, pExpr, 0);
  if( db->mallocFailed==0 ){
    sqlite3ExprIfFalse(pParse, pCopy, dest, jumpIfNull);
  }
  sqlite3ExprDelete(db, pCopy);
}

/*
** Expression pVar is guaranteed to be an SQL variable. pExpr may be any
** type of expression.
**
** If pExpr is a simple SQL value - an integer, real, string, blob
** or NULL value - then the VDBE currently being prepared is configured
** to re-prepare each time a new value is bound to variable pVar.
**
** Additionally, if pExpr is a simple SQL value and the value is the
** same as that currently bound to variable pVar, non-zero is returned.
** Otherwise, if the values are not the same or if pExpr is not a simple
** SQL value, zero is returned.
*/
static int exprCompareVariable(Parse *pParse, Expr *pVar, Expr *pExpr){
  int res = 0;
  int iVar;
  sqlite3_value *pL, *pR = 0;
  
  sqlite3ValueFromExpr(pParse->db, pExpr, SQLITE_UTF8, SQLITE_AFF_BLOB, &pR);
  if( pR ){
    iVar = pVar->iColumn;
    sqlite3VdbeSetVarmask(pParse->pVdbe, iVar);
    pL = sqlite3VdbeGetBoundValue(pParse->pReprepare, iVar, SQLITE_AFF_BLOB);
    if( pL ){
      if( sqlite3_value_type(pL)==SQLITE_TEXT ){
        sqlite3_value_text(pL); /* Make sure the encoding is UTF-8 */
      }
      res =  0==sqlite3MemCompare(pL, pR, 0);
    }
    sqlite3ValueFree(pR);
    sqlite3ValueFree(pL);
  }

  return res;
}

/*
** Do a deep comparison of two expression trees.  Return 0 if the two
** expressions are completely identical.  Return 1 if they differ only
** by a COLLATE operator at the top level.  Return 2 if there are differences
** other than the top-level COLLATE operator.
**
** If any subelement of pB has Expr.iTable==(-1) then it is allowed
** to compare equal to an equivalent element in pA with Expr.iTable==iTab.
**
** The pA side might be using TK_REGISTER.  If that is the case and pB is
** not using TK_REGISTER but is otherwise equivalent, then still return 0.
**
** Sometimes this routine will return 2 even if the two expressions
** really are equivalent.  If we cannot prove that the expressions are
** identical, we return 2 just to be safe.  So if this routine
** returns 2, then you do not really know for certain if the two
** expressions are the same.  But if you get a 0 or 1 return, then you
** can be sure the expressions are the same.  In the places where
** this routine is used, it does not hurt to get an extra 2 - that
** just might result in some slightly slower code.  But returning
** an incorrect 0 or 1 could lead to a malfunction.
**
** If pParse is not NULL then TK_VARIABLE terms in pA with bindings in
** pParse->pReprepare can be matched against literals in pB.  The 
** pParse->pVdbe->expmask bitmask is updated for each variable referenced.
** If pParse is NULL (the normal case) then any TK_VARIABLE term in 
** Argument pParse should normally be NULL. If it is not NULL and pA or
** pB causes a return value of 2.
*/
int sqlite3ExprCompare(Parse *pParse, Expr *pA, Expr *pB, int iTab){
  u32 combinedFlags;
  if( pA==0 || pB==0 ){
    return pB==pA ? 0 : 2;
  }
  if( pParse && pA->op==TK_VARIABLE && exprCompareVariable(pParse, pA, pB) ){
    return 0;
  }
  combinedFlags = pA->flags | pB->flags;
  if( combinedFlags & EP_IntValue ){
    if( (pA->flags&pB->flags&EP_IntValue)!=0 && pA->u.iValue==pB->u.iValue ){
      return 0;
    }
    return 2;
  }
  if( pA->op!=pB->op ){
    if( pA->op==TK_COLLATE && sqlite3ExprCompare(pParse, pA->pLeft,pB,iTab)<2 ){
      return 1;
    }
    if( pB->op==TK_COLLATE && sqlite3ExprCompare(pParse, pA,pB->pLeft,iTab)<2 ){
      return 1;
    }
    return 2;
  }
  if( pA->op!=TK_COLUMN && pA->op!=TK_AGG_COLUMN && pA->u.zToken ){
    if( pA->op==TK_FUNCTION ){
      if( sqlite3StrICmp(pA->u.zToken,pB->u.zToken)!=0 ) return 2;
    }else if( strcmp(pA->u.zToken,pB->u.zToken)!=0 ){
      return pA->op==TK_COLLATE ? 1 : 2;
    }
  }
  if( (pA->flags & EP_Distinct)!=(pB->flags & EP_Distinct) ) return 2;
  if( ALWAYS((combinedFlags & EP_TokenOnly)==0) ){
    if( combinedFlags & EP_xIsSelect ) return 2;
    if( sqlite3ExprCompare(pParse, pA->pLeft, pB->pLeft, iTab) ) return 2;
    if( sqlite3ExprCompare(pParse, pA->pRight, pB->pRight, iTab) ) return 2;
    if( sqlite3ExprListCompare(pA->x.pList, pB->x.pList, iTab) ) return 2;
    if( ALWAYS((combinedFlags & EP_Reduced)==0) && pA->op!=TK_STRING ){
      if( pA->iColumn!=pB->iColumn ) return 2;
      if( pA->iTable!=pB->iTable 
       && (pA->iTable!=iTab || NEVER(pB->iTable>=0)) ) return 2;
    }
  }
  return 0;
}

/*
** Compare two ExprList objects.  Return 0 if they are identical and 
** non-zero if they differ in any way.
**
** If any subelement of pB has Expr.iTable==(-1) then it is allowed
** to compare equal to an equivalent element in pA with Expr.iTable==iTab.
**
** This routine might return non-zero for equivalent ExprLists.  The
** only consequence will be disabled optimizations.  But this routine
** must never return 0 if the two ExprList objects are different, or
** a malfunction will result.
**
** Two NULL pointers are considered to be the same.  But a NULL pointer
** always differs from a non-NULL pointer.
*/
int sqlite3ExprListCompare(ExprList *pA, ExprList *pB, int iTab){
  int i;
  if( pA==0 && pB==0 ) return 0;
  if( pA==0 || pB==0 ) return 1;
  if( pA->nExpr!=pB->nExpr ) return 1;
  for(i=0; i<pA->nExpr; i++){
    Expr *pExprA = pA->a[i].pExpr;
    Expr *pExprB = pB->a[i].pExpr;
    if( pA->a[i].sortOrder!=pB->a[i].sortOrder ) return 1;
    if( sqlite3ExprCompare(0, pExprA, pExprB, iTab) ) return 1;
  }
  return 0;
}

/*
** Like sqlite3ExprCompare() except COLLATE operators at the top-level
** are ignored.
*/
int sqlite3ExprCompareSkip(Expr *pA, Expr *pB, int iTab){
  return sqlite3ExprCompare(0,
             sqlite3ExprSkipCollate(pA),
             sqlite3ExprSkipCollate(pB),
             iTab);
}

/*
** Return true if we can prove the pE2 will always be true if pE1 is
** true.  Return false if we cannot complete the proof or if pE2 might
** be false.  Examples:
**
**     pE1: x==5       pE2: x==5             Result: true
**     pE1: x>0        pE2: x==5             Result: false
**     pE1: x=21       pE2: x=21 OR y=43     Result: true
**     pE1: x!=123     pE2: x IS NOT NULL    Result: true
**     pE1: x!=?1      pE2: x IS NOT NULL    Result: true
**     pE1: x IS NULL  pE2: x IS NOT NULL    Result: false
**     pE1: x IS ?2    pE2: x IS NOT NULL    Reuslt: false
**
** When comparing TK_COLUMN nodes between pE1 and pE2, if pE2 has
** Expr.iTable<0 then assume a table number given by iTab.
**
** If pParse is not NULL, then the values of bound variables in pE1 are 
** compared against literal values in pE2 and pParse->pVdbe->expmask is
** modified to record which bound variables are referenced.  If pParse 
** is NULL, then false will be returned if pE1 contains any bound variables.
**
** When in doubt, return false.  Returning true might give a performance
** improvement.  Returning false might cause a performance reduction, but
** it will always give the correct answer and is hence always safe.
*/
int sqlite3ExprImpliesExpr(Parse *pParse, Expr *pE1, Expr *pE2, int iTab){
  if( sqlite3ExprCompare(pParse, pE1, pE2, iTab)==0 ){
    return 1;
  }
  if( pE2->op==TK_OR
   && (sqlite3ExprImpliesExpr(pParse, pE1, pE2->pLeft, iTab)
             || sqlite3ExprImpliesExpr(pParse, pE1, pE2->pRight, iTab) )
  ){
    return 1;
  }
  if( pE2->op==TK_NOTNULL && pE1->op!=TK_ISNULL && pE1->op!=TK_IS ){
    Expr *pX = sqlite3ExprSkipCollate(pE1->pLeft);
    testcase( pX!=pE1->pLeft );
    if( sqlite3ExprCompare(pParse, pX, pE2->pLeft, iTab)==0 ) return 1;
  }
  return 0;
}

/*
** An instance of the following structure is used by the tree walker
** to determine if an expression can be evaluated by reference to the
** index only, without having to do a search for the corresponding
** table entry.  The IdxCover.pIdx field is the index.  IdxCover.iCur
** is the cursor for the table.
*/
struct IdxCover {
  Index *pIdx;     /* The index to be tested for coverage */
  int iCur;        /* Cursor number for the table corresponding to the index */
};

/*
** Check to see if there are references to columns in table 
** pWalker->u.pIdxCover->iCur can be satisfied using the index
** pWalker->u.pIdxCover->pIdx.
*/
static int exprIdxCover(Walker *pWalker, Expr *pExpr){
  if( pExpr->op==TK_COLUMN
   && pExpr->iTable==pWalker->u.pIdxCover->iCur
   && sqlite3ColumnOfIndex(pWalker->u.pIdxCover->pIdx, pExpr->iColumn)<0
  ){
    pWalker->eCode = 1;
    return WRC_Abort;
  }
  return WRC_Continue;
}

/*
** Determine if an index pIdx on table with cursor iCur contains will
** the expression pExpr.  Return true if the index does cover the
** expression and false if the pExpr expression references table columns
** that are not found in the index pIdx.
**
** An index covering an expression means that the expression can be
** evaluated using only the index and without having to lookup the
** corresponding table entry.
*/
int sqlite3ExprCoveredByIndex(
  Expr *pExpr,        /* The index to be tested */
  int iCur,           /* The cursor number for the corresponding table */
  Index *pIdx         /* The index that might be used for coverage */
){
  Walker w;
  struct IdxCover xcov;
  memset(&w, 0, sizeof(w));
  xcov.iCur = iCur;
  xcov.pIdx = pIdx;
  w.xExprCallback = exprIdxCover;
  w.u.pIdxCover = &xcov;
  sqlite3WalkExpr(&w, pExpr);
  return !w.eCode;
}


/*
** An instance of the following structure is used by the tree walker
** to count references to table columns in the arguments of an 
** aggregate function, in order to implement the
** sqlite3FunctionThisSrc() routine.
*/
struct SrcCount {
  SrcList *pSrc;   /* One particular FROM clause in a nested query */
  int nThis;       /* Number of references to columns in pSrcList */
  int nOther;      /* Number of references to columns in other FROM clauses */
};

/*
** Count the number of references to columns.
*/
static int exprSrcCount(Walker *pWalker, Expr *pExpr){
  /* The NEVER() on the second term is because sqlite3FunctionUsesThisSrc()
  ** is always called before sqlite3ExprAnalyzeAggregates() and so the
  ** TK_COLUMNs have not yet been converted into TK_AGG_COLUMN.  If
  ** sqlite3FunctionUsesThisSrc() is used differently in the future, the
  ** NEVER() will need to be removed. */
  if( pExpr->op==TK_COLUMN || NEVER(pExpr->op==TK_AGG_COLUMN) ){
    int i;
    struct SrcCount *p = pWalker->u.pSrcCount;
    SrcList *pSrc = p->pSrc;
    int nSrc = pSrc ? pSrc->nSrc : 0;
    for(i=0; i<nSrc; i++){
      if( pExpr->iTable==pSrc->a[i].iCursor ) break;
    }
    if( i<nSrc ){
      p->nThis++;
    }else{
      p->nOther++;
    }
  }
  return WRC_Continue;
}

/*
** Determine if any of the arguments to the pExpr Function reference
** pSrcList.  Return true if they do.  Also return true if the function
** has no arguments or has only constant arguments.  Return false if pExpr
** references columns but not columns of tables found in pSrcList.
*/
int sqlite3FunctionUsesThisSrc(Expr *pExpr, SrcList *pSrcList){
  Walker w;
  struct SrcCount cnt;
  assert( pExpr->op==TK_AGG_FUNCTION );
  w.xExprCallback = exprSrcCount;
  w.xSelectCallback = 0;
  w.u.pSrcCount = &cnt;
  cnt.pSrc = pSrcList;
  cnt.nThis = 0;
  cnt.nOther = 0;
  sqlite3WalkExprList(&w, pExpr->x.pList);
  return cnt.nThis>0 || cnt.nOther==0;
}

/*
** Add a new element to the pAggInfo->aCol[] array.  Return the index of
** the new element.  Return a negative number if malloc fails.
*/
static int addAggInfoColumn(sqlite3 *db, AggInfo *pInfo){
  int i;
  pInfo->aCol = sqlite3ArrayAllocate(
       db,
       pInfo->aCol,
       sizeof(pInfo->aCol[0]),
       &pInfo->nColumn,
       &i
  );
  return i;
}    

/*
** Add a new element to the pAggInfo->aFunc[] array.  Return the index of
** the new element.  Return a negative number if malloc fails.
*/
static int addAggInfoFunc(sqlite3 *db, AggInfo *pInfo){
  int i;
  pInfo->aFunc = sqlite3ArrayAllocate(
       db, 
       pInfo->aFunc,
       sizeof(pInfo->aFunc[0]),
       &pInfo->nFunc,
       &i
  );
  return i;
}    

/*
** This is the xExprCallback for a tree walker.  It is used to
** implement sqlite3ExprAnalyzeAggregates().  See sqlite3ExprAnalyzeAggregates
** for additional information.
*/
static int analyzeAggregate(Walker *pWalker, Expr *pExpr){
  int i;
  NameContext *pNC = pWalker->u.pNC;
  Parse *pParse = pNC->pParse;
  SrcList *pSrcList = pNC->pSrcList;
  AggInfo *pAggInfo = pNC->pAggInfo;

  switch( pExpr->op ){
    case TK_AGG_COLUMN:
    case TK_COLUMN: {
      testcase( pExpr->op==TK_AGG_COLUMN );
      testcase( pExpr->op==TK_COLUMN );
      /* Check to see if the column is in one of the tables in the FROM
      ** clause of the aggregate query */
      if( ALWAYS(pSrcList!=0) ){
        struct SrcList_item *pItem = pSrcList->a;
        for(i=0; i<pSrcList->nSrc; i++, pItem++){
          struct AggInfo_col *pCol;
          assert( !ExprHasProperty(pExpr, EP_TokenOnly|EP_Reduced) );
          if( pExpr->iTable==pItem->iCursor ){
            /* If we reach this point, it means that pExpr refers to a table
            ** that is in the FROM clause of the aggregate query.  
            **
            ** Make an entry for the column in pAggInfo->aCol[] if there
            ** is not an entry there already.
            */
            int k;
            pCol = pAggInfo->aCol;
            for(k=0; k<pAggInfo->nColumn; k++, pCol++){
              if( pCol->iTable==pExpr->iTable &&
                  pCol->iColumn==pExpr->iColumn ){
                break;
              }
            }
            if( (k>=pAggInfo->nColumn)
             && (k = addAggInfoColumn(pParse->db, pAggInfo))>=0 
            ){
              pCol = &pAggInfo->aCol[k];
              pCol->pTab = pExpr->pTab;
              pCol->iTable = pExpr->iTable;
              pCol->iColumn = pExpr->iColumn;
              pCol->iMem = ++pParse->nMem;
              pCol->iSorterColumn = -1;
              pCol->pExpr = pExpr;
              if( pAggInfo->pGroupBy ){
                int j, n;
                ExprList *pGB = pAggInfo->pGroupBy;
                struct ExprList_item *pTerm = pGB->a;
                n = pGB->nExpr;
                for(j=0; j<n; j++, pTerm++){
                  Expr *pE = pTerm->pExpr;
                  if( pE->op==TK_COLUMN && pE->iTable==pExpr->iTable &&
                      pE->iColumn==pExpr->iColumn ){
                    pCol->iSorterColumn = j;
                    break;
                  }
                }
              }
              if( pCol->iSorterColumn<0 ){
                pCol->iSorterColumn = pAggInfo->nSortingColumn++;
              }
            }
            /* There is now an entry for pExpr in pAggInfo->aCol[] (either
            ** because it was there before or because we just created it).
            ** Convert the pExpr to be a TK_AGG_COLUMN referring to that
            ** pAggInfo->aCol[] entry.
            */
            ExprSetVVAProperty(pExpr, EP_NoReduce);
            pExpr->pAggInfo = pAggInfo;
            pExpr->op = TK_AGG_COLUMN;
            pExpr->iAgg = (i16)k;
            break;
          } /* endif pExpr->iTable==pItem->iCursor */
        } /* end loop over pSrcList */
      }
      return WRC_Prune;
    }
    case TK_AGG_FUNCTION: {
      if( (pNC->ncFlags & NC_InAggFunc)==0
       && pWalker->walkerDepth==pExpr->op2
      ){
        /* Check to see if pExpr is a duplicate of another aggregate 
        ** function that is already in the pAggInfo structure
        */
        struct AggInfo_func *pItem = pAggInfo->aFunc;
        for(i=0; i<pAggInfo->nFunc; i++, pItem++){
          if( sqlite3ExprCompare(0, pItem->pExpr, pExpr, -1)==0 ){
            break;
          }
        }
        if( i>=pAggInfo->nFunc ){
          /* pExpr is original.  Make a new entry in pAggInfo->aFunc[]
          */
          u8 enc = ENC(pParse->db);
          i = addAggInfoFunc(pParse->db, pAggInfo);
          if( i>=0 ){
            assert( !ExprHasProperty(pExpr, EP_xIsSelect) );
            pItem = &pAggInfo->aFunc[i];
            pItem->pExpr = pExpr;
            pItem->iMem = ++pParse->nMem;
            assert( !ExprHasProperty(pExpr, EP_IntValue) );
            pItem->pFunc = sqlite3FindFunction(pParse->db,
                   pExpr->u.zToken, 
                   pExpr->x.pList ? pExpr->x.pList->nExpr : 0, enc, 0);
            if( pExpr->flags & EP_Distinct ){
              pItem->iDistinct = pParse->nTab++;
            }else{
              pItem->iDistinct = -1;
            }
          }
        }
        /* Make pExpr point to the appropriate pAggInfo->aFunc[] entry
        */
        assert( !ExprHasProperty(pExpr, EP_TokenOnly|EP_Reduced) );
        ExprSetVVAProperty(pExpr, EP_NoReduce);
        pExpr->iAgg = (i16)i;
        pExpr->pAggInfo = pAggInfo;
        return WRC_Prune;
      }else{
        return WRC_Continue;
      }
    }
  }
  return WRC_Continue;
}
static int analyzeAggregatesInSelect(Walker *pWalker, Select *pSelect){
  UNUSED_PARAMETER(pSelect);
  pWalker->walkerDepth++;
  return WRC_Continue;
}
static void analyzeAggregatesInSelectEnd(Walker *pWalker, Select *pSelect){
  UNUSED_PARAMETER(pSelect);
  pWalker->walkerDepth--;
}

/*
** Analyze the pExpr expression looking for aggregate functions and
** for variables that need to be added to AggInfo object that pNC->pAggInfo
** points to.  Additional entries are made on the AggInfo object as
** necessary.
**
** This routine should only be called after the expression has been
** analyzed by sqlite3ResolveExprNames().
*/
void sqlite3ExprAnalyzeAggregates(NameContext *pNC, Expr *pExpr){
  Walker w;
  w.xExprCallback = analyzeAggregate;
  w.xSelectCallback = analyzeAggregatesInSelect;
  w.xSelectCallback2 = analyzeAggregatesInSelectEnd;
  w.walkerDepth = 0;
  w.u.pNC = pNC;
  assert( pNC->pSrcList!=0 );
  sqlite3WalkExpr(&w, pExpr);
}

/*
** Call sqlite3ExprAnalyzeAggregates() for every expression in an
** expression list.  Return the number of errors.
**
** If an error is found, the analysis is cut short.
*/
void sqlite3ExprAnalyzeAggList(NameContext *pNC, ExprList *pList){
  struct ExprList_item *pItem;
  int i;
  if( pList ){
    for(pItem=pList->a, i=0; i<pList->nExpr; i++, pItem++){
      sqlite3ExprAnalyzeAggregates(pNC, pItem->pExpr);
    }
  }
}

/*
** Allocate a single new register for use to hold some intermediate result.
*/
int sqlite3GetTempReg(Parse *pParse){
  if( pParse->nTempReg==0 ){
    return ++pParse->nMem;
  }
  return pParse->aTempReg[--pParse->nTempReg];
}

/*
** Deallocate a register, making available for reuse for some other
** purpose.
**
** If a register is currently being used by the column cache, then
** the deallocation is deferred until the column cache line that uses
** the register becomes stale.
*/
void sqlite3ReleaseTempReg(Parse *pParse, int iReg){
  if( iReg && pParse->nTempReg<ArraySize(pParse->aTempReg) ){
    int i;
    struct yColCache *p;
    for(i=0, p=pParse->aColCache; i<pParse->nColCache; i++, p++){
      if( p->iReg==iReg ){
        p->tempReg = 1;
        return;
      }
    }
    pParse->aTempReg[pParse->nTempReg++] = iReg;
  }
}

/*
** Allocate or deallocate a block of nReg consecutive registers.
*/
int sqlite3GetTempRange(Parse *pParse, int nReg){
  int i, n;
  if( nReg==1 ) return sqlite3GetTempReg(pParse);
  i = pParse->iRangeReg;
  n = pParse->nRangeReg;
  if( nReg<=n ){
    assert( !usedAsColumnCache(pParse, i, i+n-1) );
    pParse->iRangeReg += nReg;
    pParse->nRangeReg -= nReg;
  }else{
    i = pParse->nMem+1;
    pParse->nMem += nReg;
  }
  return i;
}
void sqlite3ReleaseTempRange(Parse *pParse, int iReg, int nReg){
  if( nReg==1 ){
    sqlite3ReleaseTempReg(pParse, iReg);
    return;
  }
  sqlite3ExprCacheRemove(pParse, iReg, nReg);
  if( nReg>pParse->nRangeReg ){
    pParse->nRangeReg = nReg;
    pParse->iRangeReg = iReg;
  }
}

/*
** Mark all temporary registers as being unavailable for reuse.
*/
void sqlite3ClearTempRegCache(Parse *pParse){
  pParse->nTempReg = 0;
  pParse->nRangeReg = 0;
}

/*
** Validate that no temporary register falls within the range of
** iFirst..iLast, inclusive.  This routine is only call from within assert()
** statements.
*/
#ifdef SQLITE_DEBUG
int sqlite3NoTempsInRange(Parse *pParse, int iFirst, int iLast){
  int i;
  if( pParse->nRangeReg>0
   && pParse->iRangeReg+pParse->nRangeReg > iFirst
   && pParse->iRangeReg <= iLast
  ){
     return 0;
  }
  for(i=0; i<pParse->nTempReg; i++){
    if( pParse->aTempReg[i]>=iFirst && pParse->aTempReg[i]<=iLast ){
      return 0;
    }
  }
  return 1;
}
#endif /* SQLITE_DEBUG */
