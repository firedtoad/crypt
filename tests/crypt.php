<?php

if(PHP_VERSION<7)
{
    exit("need PHP_VERSION > 7.0");
}

if(!extension_loaded('crypt'))
{
    exit("need crypt extension");
}
/**
 * extension helper class for skynet login client
 * @author dietoad
 * @see https://github.com/cloudwu/skynet/blob/master/lualib-src/lua-crypt.c
 */
class Crypt
{
    /**
     * generate 8 bit random client key
     * @return string
     */
   public static function randomkey()
   {
       return randomkey();
   }
   /**
    * calculate hash key with specific string   
    * @param string $str
    * @return string
    */
   public static function hashkey($str)
   {
       return hashkey($str);
   }
   /**
    * same as bin2hex
    * @param string $str binary string
    * @return string
    */
   public static function tohex($str)
   {
       return tohex($str);
   }
   /**
    * same as hex2bin
    * @param string $str hex string
    * @return string
    */
   public static function fromhex($str)
   {
       return fromhex($str);
   }
   
   /**
    * perform des encode with 8bits key
    * @param string $key   8bits key
    * @param string $data 
    * @return string
    */
   public static function desencode($key,$data)
   {
       return desencode($key,$data);
   }
   
   /**
    * perform des decode with 8bits key
    * @param string $key   8bits key
    * @param string $data
    * @return string
    */
   public static function desdecode($key,$data)
   {
       return desdecode($key,$data);
   }
   
   /**
    * perform hmac with 8bits key and 8bits data
    * @param string $key   8bits key
    * @param string $data  8bits key
    * @return string
    */
   public static function hmac64($data,$key)
   {
       return hmac64($data,$key);
   }
   /**
    * perform hmac_md5 with 8bits key and 8bits data
    * @param string $key   8bits data
    * @param string $data  8bits key
    * @return string
    */
   public static function hmac_md5($data,$key)
   {
       return hmac_md5($data,$key);
   }
   /**
    * perform hmac_hash with 8bits key and 8bits data
    * @param string $key   8bits key
    * @param string $data  8bits data
    * @return string
    */
   public static function hmac_hash($key,$data)
   {
       return hash_hmac($key,$data);
   }
   
   /**
    * perform hmac_sha1 
    * @param string $key   
    * @param string $data  
    * @return string
    */
   public static function hmac_sha1($key,$data)
   {
       return hash_hmac('sha1',$data,$key,true);
   }
   
   /**
    * perform xor_str
    * @param string $s1
    * @param string $s2
    * @return string
    */
   public static function xor_str($s1,$s2)
   {
       return xor_str($s1,$s2);
   }
   
   /**
    * calculate the secret with give privte key and public key
    * @param string $pub 8bits public key
    * @param string $pri 8bits private key
    */
   public static function dhsecret($pub,$pri)
   {
       return dhsecret($pub,$pri);
   }
   /**
    * calculate the public key of the given private key
    * @param string $key 8bits private key
    */
   public static function dhexchange($key)
   {
       return dhexchange($key);
   }
}
