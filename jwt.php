<?php

/**
 * demonstrate the basic concepts of JSON Web Tokens' core features
 *
 * @see https://en.wikipedia.org/wiki/JSON_Web_Token
 * @see https://tools.ietf.org/html/rfc7519
 */

class JWT {

    const ALGO = 'sha256';

    const HEADER = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];

    /**
     * get a dot-concatenated string representation of the json-encoded payload with signature
     *
     * @param mixed $payload
     * @param string $key
     * @return string
     */

    public function encode($payload, string $key) : string {
        $body = [self::HEADER, $payload];
        $json = array_map('json_encode', $body);
        $base = array_map('base64_encode', $json);
        $unsigned = implode('.', $base);    // data to be signed
        $signature = base64_encode(hash_hmac(self::ALGO, $key, $unsigned));   // generate encrypted hash
        $signed = "$unsigned.$signature";   // append signature
        return $signed;
    }

    /**
     * get the actual values that have ben signed
     *
     * @param string $jwt
     * @param string $key
     * @return mixed
     */

    public function decode(string $jwt, string $key){
        $parts = $this->verify($jwt, $key);   // check first
        $body = next($parts);   // return payload only
        $json = base64_decode($body);
        $payload = json_decode($json);
        return $payload;
    }

    /**
     * verify that the payload's signature was hashed with the actual encryption key
     *
     * @param string $jwt
     * @param string $key
     * @throws Exception
     * @return array
     */

    private function verify(string $jwt, string $key) : array {
        list($header, $payload, $signature) = $parts = explode('.', $jwt);   // store parts to be returned
        $unsigned = "$header.$payload";
        $validsignature = base64_encode(hash_hmac(self::ALGO, $key, $unsigned));   // get real hash
        if($signature === $validsignature) return $parts;   // check if encryption was done with the same key
        throw new Exception('invalid signature') ;
    }

}



/*

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

*/
