# class JWT

Simple class for the basic functionality to encode/decode JWT (JSON Web Tokens) in PHP.


# usage

```php
<?php

require 'jwt.php';

define('JWTKEY', 'SUPERSECRETPRIVATEKEY');

$payload = [
    'mynameis' => 'chorn',
    'email' => 'job@chorn.de',
    'location' => 'germany',
];

$JWT = new JWT;

// get signed token for values

$token = $JWT->encode($payload, JWTKEY);
echo $token, "\n";

// verify and decode a given valid token

try {
    $payload = $JWT->decode($token, JWTKEY);
    print_r($payload);
}
catch (Exception $e){
    echo $e->getMessage();
}

// try to verify and decode an INVALID token

try {
    $token .= 'INVALID';
    $payload = $JWT->decode($token, JWTKEY);
    print_r($payload);
}
catch (Exception $e){
    echo $e->getMessage();
}
```