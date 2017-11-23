/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2017 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_crypt.h"
#include "crypt.h"


/* True global resources - no need for thread safety here */
static int le_crypt;

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("crypt.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_crypt_globals, crypt_globals)
    STD_PHP_INI_ENTRY("crypt.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_crypt_globals, crypt_globals)
PHP_INI_END()
*/
/* }}} */


PHP_FUNCTION(hashkey)
{
	char *buffer = NULL;
	size_t len=0;
	int argc = ZEND_NUM_ARGS();
	if (zend_parse_parameters(argc, "s", &buffer, &len) == FAILURE)
		return;
	uint8_t realkey[8];
	Hash(buffer, (int)len, realkey);
	zend_string *rt=zend_string_init(realkey,8,0);
	RETURN_STR(rt);
}

PHP_FUNCTION(randomkey)
{
	uint8_t realkey[8];
	Randomkey(realkey);
	zend_string *rt = zend_string_init(realkey, 8, 0);
	RETURN_STR(rt);
}

PHP_FUNCTION(desencode)
{
	uint32_t SK[32];
	char *key = NULL, *text = NULL;
	size_t key_len = 0, textsz = 0;
	int argc = ZEND_NUM_ARGS();
	if (zend_parse_parameters(argc, "ss", &key, &key_len, &text, &textsz) == FAILURE)
		return;
	des_main_ks(SK, key);
	size_t chunksz = (textsz + 8) & ~7;
	uint8_t tmp[SMALL_CHUNK];
	zend_string *buffer = NULL; 
	if (chunksz > SMALL_CHUNK)
	{
		buffer = zend_string_alloc(chunksz,0);
	}
	else {
		buffer= zend_string_init(tmp, chunksz, 0);
	}
	int i;
	for (i = 0; i < (int)textsz - 7; i += 8)
	{
		des_crypt(SK, text + i, buffer->val + i);
	}
	int bytes = (int)textsz - i;
	uint8_t tail[8];
	int j;
	for (j = 0; j < 8; j++)
	{
		if (j < bytes)
		{
			tail[j] = text[i + j];
		}
		else if (j == bytes)
		{
			tail[j] = 0x80;
		}
		else
		{
			tail[j] = 0;
		}
	}
	des_crypt(SK, tail, buffer->val + i);
	zend_string *ret = zend_string_init(buffer->val, chunksz, 0);
	RETURN_STR(ret);
}
PHP_FUNCTION(desdecode)
{
	uint32_t SK[32];
	uint32_t ESK[32];
	char *key = NULL, *text = NULL;
	size_t key_len = 0, textsz = 0;
	int argc = ZEND_NUM_ARGS();
	if (zend_parse_parameters(argc, "ss", &key, &key_len, &text, &textsz) == FAILURE)
		return;
	if ((textsz & 7) || textsz == 0)
	{
		php_error(E_WARNING, "Invalid des crypt text length %d line %d", textsz,__LINE__);
	}
	des_main_ks(ESK, key);
	int i;
	for (i = 0; i < 32; i += 2)
	{
		SK[i] = ESK[30 - i];
		SK[i + 1] = ESK[31 - i];
	}
	uint8_t tmp[SMALL_CHUNK] = { 0 };
	zend_string *buffer = NULL;
	if (textsz > SMALL_CHUNK)
	{
		buffer = zend_string_alloc(textsz, 0);
	}
	else {
		buffer = zend_string_init(tmp, textsz, 0);
	}

	for (i = 0; i < textsz; i += 8)
	{
		des_crypt(SK, text + i, (uint8_t*)&buffer->val[i]);
	}
	int padding = 1;
	for (i = (int)textsz - 1; i >= (int)textsz - 8; i--)
	{
		if ((uint8_t)buffer->val[i] == 0)
		{
			padding++;
		}
		else if ((uint8_t)buffer->val[i] == 0x80)
		{
			break;
		}
		else
		{
			php_error(E_WARNING,"Invalid des crypt text %d index %d char %d textsz %d",__LINE__,i, buffer->val[i], textsz);
		}
	}
	if (padding > 8)
	{
		php_error(E_WARNING,"Invalid des crypt text %d",__LINE__);
	}
	zend_string *ret=zend_string_init(buffer->val, textsz - padding,0);
	RETURN_STR(ret);
}


static char hexconvtab[] = "0123456789abcdef";
static zend_string *php_bin2hex(const unsigned char *old, const size_t oldlen)
{
	zend_string *result;
	size_t i, j;

	result = zend_string_safe_alloc(oldlen, 2 * sizeof(char), 0, 0);

	for (i = j = 0; i < oldlen; i++) {
		ZSTR_VAL(result)[j++] = hexconvtab[old[i] >> 4];
		ZSTR_VAL(result)[j++] = hexconvtab[old[i] & 15];
	}
	ZSTR_VAL(result)[j] = '\0';

	return result;
}

static zend_string *php_hex2bin(const unsigned char *old, const size_t oldlen)
{
	size_t target_length = oldlen >> 1;
	zend_string *str = zend_string_alloc(target_length, 0);
	unsigned char *ret = (unsigned char *)ZSTR_VAL(str);
	size_t i, j;

	for (i = j = 0; i < target_length; i++) {
		unsigned char c = old[j++];
		unsigned char l = c & ~0x20;
		int is_letter = ((unsigned int)((l - 'A') ^ (l - 'F' - 1))) >> (8 * sizeof(unsigned int) - 1);
		unsigned char d;

		/* basically (c >= '0' && c <= '9') || (l >= 'A' && l <= 'F') */
		if (EXPECTED((((c ^ '0') - 10) >> (8 * sizeof(unsigned int) - 1)) | is_letter)) {
			d = (l - 0x10 - 0x27 * is_letter) << 4;
		}
		else {
			zend_string_free(str);
			return NULL;
		}
		c = old[j++];
		l = c & ~0x20;
		is_letter = ((unsigned int)((l - 'A') ^ (l - 'F' - 1))) >> (8 * sizeof(unsigned int) - 1);
		if (EXPECTED((((c ^ '0') - 10) >> (8 * sizeof(unsigned int) - 1)) | is_letter)) {
			d |= l - 0x10 - 0x27 * is_letter;
		}
		else {
			zend_string_free(str);
			return NULL;
		}
		ret[i] = d;
	}
	ret[i] = '\0';

	return str;
}

PHP_FUNCTION(tohex)
{
	zend_string *result=NULL;
	zend_string *data=NULL;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
		ZEND_PARSE_PARAMETERS_END();

	result = php_bin2hex((unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data));

	if (!result) {
		RETURN_FALSE;
	}
	RETURN_STR(result);
}

PHP_FUNCTION(fromhex)
{
	zend_string *result = NULL;
	zend_string *data = NULL;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
		ZEND_PARSE_PARAMETERS_END();

	result = php_hex2bin((unsigned char *)ZSTR_VAL(data), ZSTR_LEN(data));

	if (!result) {
		RETURN_FALSE;
	}
	RETURN_STR(result);
}


void read64(zend_string *data, zend_string *sec, uint32_t xx[2], uint32_t yy[2])
{
	uint8_t *x = data->val;
	uint8_t *y = sec->val;
	xx[0] = x[0] | x[1] << 8 | x[2] << 16 | x[3] << 24;
	xx[1] = x[4] | x[5] << 8 | x[6] << 16 | x[7] << 24;
	yy[0] = y[0] | y[1] << 8 | y[2] << 16 | y[3] << 24;
	yy[1] = y[4] | y[5] << 8 | y[6] << 16 | y[7] << 24;
}


uint8_t* put64(uint8_t tmp[8],uint32_t result[2])
{
	tmp[0] = result[0] & 0xff;
	tmp[1] = (result[0] >> 8) & 0xff;
	tmp[2] = (result[0] >> 16) & 0xff;
	tmp[3] = (result[0] >> 24) & 0xff;
	tmp[4] = result[1] & 0xff;
	tmp[5] = (result[1] >> 8) & 0xff;
	tmp[6] = (result[1] >> 16) & 0xff;
	tmp[7] = (result[1] >> 24) & 0xff;
	return tmp;
}
uint8_t* push64(uint8_t tmp[8], uint64_t r)
{
	tmp[0] = r & 0xff;
	tmp[1] = (r >> 8) & 0xff;
	tmp[2] = (r >> 16) & 0xff;
	tmp[3] = (r >> 24) & 0xff;
	tmp[4] = (r >> 32) & 0xff;
	tmp[5] = (r >> 40) & 0xff;
	tmp[6] = (r >> 48) & 0xff;
	tmp[7] = (r >> 56) & 0xff;
	return tmp;
}
PHP_FUNCTION(hmac64)
{
	zend_string *data = NULL;
	zend_string *sec = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(data)
		Z_PARAM_STR(sec)
		ZEND_PARSE_PARAMETERS_END();
	uint32_t xx[2], yy[2];
	read64(data, sec, xx, yy);
	uint32_t result[2];
	hmac(xx, yy, result);
	uint8_t tmp[8];
	put64(tmp, result);
	RETURN_STRINGL(tmp, 8);
}

PHP_FUNCTION(hmac64_md5)
{
	zend_string *data = NULL;
	zend_string *sec = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(data)
		Z_PARAM_STR(sec)
		ZEND_PARSE_PARAMETERS_END();
	uint32_t xx[2], yy[2];
	read64(data, sec, xx, yy);
	uint32_t result[2];
	hmac_md5(xx, yy, result);
	uint8_t tmp[8];
	put64(tmp, result);
	RETURN_STRINGL(tmp, 8);
}


PHP_FUNCTION(dhexchange)
{
	zend_string *data = NULL;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(data)
	ZEND_PARSE_PARAMETERS_END();
	uint32_t xx[2];
	uint8_t *x = data->val;
	xx[0] = x[0] | x[1] << 8 | x[2] << 16 | x[3] << 24;
	xx[1] = x[4] | x[5] << 8 | x[6] << 16 | x[7] << 24;
	uint64_t x64 = (uint64_t)xx[0] | (uint64_t)xx[1] << 32;
	uint64_t r = powmodp(G, x64);
	uint8_t tmp[8];
	push64(tmp,r);
	RETURN_STRINGL(tmp, 8);
}

PHP_FUNCTION(dhsecret)
{
	zend_string *data = NULL;
	zend_string *sec = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(data)
		Z_PARAM_STR(sec)
	ZEND_PARSE_PARAMETERS_END();
	uint32_t x[2], y[2];
	read64(data, sec, x, y);
	uint64_t xx = (uint64_t)x[0] | (uint64_t)x[1] << 32;
	uint64_t yy = (uint64_t)y[0] | (uint64_t)y[1] << 32;
	uint64_t r = powmodp(xx, yy);
	uint8_t tmp[8];
	push64(tmp, r);
	RETURN_STRINGL(tmp, 8);
}

PHP_FUNCTION(hmac_hash)
{
	zend_string *xkey = NULL;
	zend_string *xtext = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(xkey)
		Z_PARAM_STR(xtext)
	ZEND_PARSE_PARAMETERS_END();
	uint32_t key[2];
	uint8_t *x = xkey->val;
	key[0] = x[0] | x[1] << 8 | x[2] << 16 | x[3] << 24;
	key[1] = x[4] | x[5] << 8 | x[6] << 16 | x[7] << 24;
	uint8_t h[8];
	Hash(xtext->val, (int)xtext->len, h);
	uint32_t htext[2];
	htext[0] = h[0] | h[1] << 8 | h[2] << 16 | h[3] << 24;
	htext[1] = h[4] | h[5] << 8 | h[6] << 16 | h[7] << 24;
	uint32_t result[2];
	hmac(htext, key, result);
	uint8_t tmp[8];
	put64(tmp,result);
	RETURN_STRINGL(tmp, 8);
}


PHP_FUNCTION(xor_str)
{
	zend_string *s1 = NULL;
	zend_string *s2 = NULL;
	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(s1)
		Z_PARAM_STR(s2)
	ZEND_PARSE_PARAMETERS_END();
	int i;
	zend_string* buffer = zend_string_safe_alloc(s1->len,1,0,0);
	for (i = 0; i < s1->len; i++)
	{
		buffer->val[i] = s1->val[i] ^ s2->val[i % s2->len];
	}
	RETURN_STR(buffer);
}



/* {{{ php_crypt_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_crypt_init_globals(zend_crypt_globals *crypt_globals)
{
	crypt_globals->global_value = 0;
	crypt_globals->global_string = NULL;
}
*/
/* }}} */

PHP_MINIT_FUNCTION(crypt)
{
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(crypt)
{
	return SUCCESS;
}

PHP_RINIT_FUNCTION(crypt)
{
#if defined(COMPILE_DL_CRYPT) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(crypt)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(crypt)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "crypt support", "enabled");
	php_info_print_table_end();


}
/* }}} */

/* {{{ crypt_functions[]
 *
 * Every user visible function must have an entry in crypt_functions[].
 */
const zend_function_entry crypt_functions[] = {
	PHP_FE(hashkey,	NULL)
	PHP_FE(randomkey,NULL)
	PHP_FE(desencode,NULL)
	PHP_FE(desdecode,NULL)
	PHP_FE(tohex,NULL)
	PHP_FE(fromhex,NULL)
	PHP_FE(hmac64,NULL)
	PHP_FE(hmac64_md5,NULL)
	PHP_FE(dhexchange,NULL)
	PHP_FE(dhsecret,NULL)
	PHP_FE(hmac_hash,NULL)
	PHP_FE(xor_str,NULL)	
	PHP_FE_END	/* Must be the last line in crypt_functions[] */
};
/* }}} */

/* {{{ crypt_module_entry
 */
zend_module_entry crypt_module_entry = {
	STANDARD_MODULE_HEADER,
	"crypt",
	crypt_functions,
	PHP_MINIT(crypt),
	PHP_MSHUTDOWN(crypt),
	PHP_RINIT(crypt),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(crypt),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(crypt),
	PHP_CRYPT_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_CRYPT
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(crypt)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
