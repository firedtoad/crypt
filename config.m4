dnl $Id$
dnl config.m4 for extension crypt

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(crypt, for crypt support,
dnl Make sure that the comment is aligned:
dnl [  --with-crypt             Include crypt support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(crypt, whether to enable crypt support,
dnl Make sure that the comment is aligned:
dnl [  --enable-crypt           Enable crypt support])

if test "$PHP_CRYPT" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-crypt -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/crypt.h"  # you most likely want to change this
  dnl if test -r $PHP_CRYPT/$SEARCH_FOR; then # path given as parameter
  dnl   CRYPT_DIR=$PHP_CRYPT
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for crypt files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       CRYPT_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$CRYPT_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the crypt distribution])
  dnl fi

  dnl # --with-crypt -> add include path
  dnl PHP_ADD_INCLUDE($CRYPT_DIR/include)

  dnl # --with-crypt -> check for lib and symbol presence
  dnl LIBNAME=crypt # you may want to change this
  dnl LIBSYMBOL=crypt # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $CRYPT_DIR/$PHP_LIBDIR, CRYPT_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_CRYPTLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong crypt lib version or lib not found])
  dnl ],[
  dnl   -L$CRYPT_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(CRYPT_SHARED_LIBADD)

  PHP_NEW_EXTENSION(crypt, crypt.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
