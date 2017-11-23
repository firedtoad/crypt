# crypt
skynet client login service need some crypt functions 
```php
<?php
include 'crypt.php';
$fd=fsockopen('127.0.0.1:8001');
function writeline($text)
{
    global $fd;
    $len=fwrite($fd, $text . "\n");
}
function unpack_line($text)
{
    $pos=strpos($text, "\n");
    if($pos)
    {
        return [substr($text, 0,-1),substr($text, -1)];
    }
    return ['',$text];
}
function read_server()
{
    global $fd;
    do{
        $text=fread($fd, 32);
        $text=unpack_line($text);
        if(!empty($text[0]))
        {
            return $text[0];
        }
    }while(1);
}


function send_request($v, $session)
{
    global $fd;
    $size = strlen($v) + 4;
    $package = pack("n", $size).$v.pack("N", $session);
    fwrite($fd, $package);
    return [$v, $session];
}

function recv_response($v)
{
     $size = strlen($v) -5;
//     local content, ok, session = string.unpack("c"..tostring(size).."B>I4", v)
    $res=unpack('Z'.$size.'data/Ccode/Nsession',$v);
//     return ok ~=0 , content, session
    return $res;
}


function read_package()
{
    global $fd;
    do{
        $text=fread($fd, 64);
        $text=unpack_package($text);
        if(!empty($text[0]))
        {
            return $text[0];
        }
    }while(1);
    
}

function unpack_package($text)
{
    $size = strlen($text);
    if( $size < 2) {
        return [null, $text];
    }
    $s=unpack('n', $text);
//     $s = ord(substr($text, 0,1)) * 256 + ord(substr($text, 1,1));
    $s=$s[1];
    if ($size < $s+2){
        return [null, $text];
    }
    return [substr($text, 2,2+$s), substr($text,2+$s)];

}


function send_package($fd, $pack)
{
    $package = pack("na".strlen($pack), strlen($pack),$pack);
    fwrite($fd, $package);
}
 function encode_token($token)
 {
     return sprintf("%s@%s:%s",
         base64_encode($token['user']),
         base64_encode($token['server']),
         base64_encode($token['pass'])
         );
 }

$private_key=Crypt::randomkey();
$str=read_server();
$challange=base64_decode($str);
$clientkey=Crypt::dhexchange($private_key);
$base_client_pub=base64_encode($clientkey);
writeline($base_client_pub);
$str=read_server();
$server_pub=base64_decode($str);
$sec=Crypt::dhsecret($server_pub, $private_key);
echo "sec=",bin2hex($sec),"\n";

$hmac=Crypt::hmac64($challange, $sec);
$base_hmac=base64_encode($hmac);
writeline($base_hmac);
$token = [
    'server' => "sample",
    'user' => "godlike",
    'pass' => "password",
];
$s=encode_token($token);
$etoken = Crypt::desencode($sec, $s);
$auth_base_64 = base64_encode($etoken);
writeline($auth_base_64);
$str=read_server();
$code=substr($str,0,3);
$sub=base64_decode(substr($str,4));
echo "code=",$code,"\n";
echo "subid=",$sub,"\n";
print("connect\n");
fclose($fd);
$index = 1;
$fd=fsockopen('127.0.0.1:8888');
$handshake = sprintf("%s@%s#%s:%d", base64_encode($token['user']), base64_encode($token['server']),base64_encode($sub) , $index);
$hmac = Crypt::hmac64(Crypt::hashkey($handshake), $sec);
send_package($fd,$handshake . ":" . base64_encode($hmac));
echo (read_package()),"\n";
$text = "echo";
send_request($text,0);
$v=(read_package());
$res=recv_response($v);
print_r($res);
fclose($fd);
$fd=fsockopen('127.0.0.1:8888');
print("connect again\n");
$index++;
$handshake = sprintf("%s@%s#%s:%d", base64_encode($token['user']), base64_encode($token['server']),base64_encode($sub) , $index);
$hmac = Crypt::hmac64(Crypt::hashkey($handshake), $sec);
send_package($fd,$handshake . ":" . base64_encode($hmac));
echo (read_package()),"\n";

send_request("fake",1);
send_request("again",2);
$v=(read_package());
$res=recv_response($v);
print_r($res);
$v=(read_package());
$res=recv_response($v);
print_r($res);


```