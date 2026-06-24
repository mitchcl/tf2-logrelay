#if defined _logrelay_curl_included
 #endinput
#endif
#define _logrelay_curl_included

// Minimal cURL extension binding for native OpenSSL hashing (curl_hash_string).

enum Openssl_Hash {
    Openssl_Hash_MD5 = 0,
    Openssl_Hash_MD4,
    Openssl_Hash_MD2,
    Openssl_Hash_SHA,
    Openssl_Hash_SHA1,
    Openssl_Hash_SHA224,
    Openssl_Hash_SHA256,
    Openssl_Hash_SHA384,
    Openssl_Hash_SHA512,
    Openssl_Hash_RIPEMD160,
};

native bool curl_hash_string(const char[] input, int dataSize, Openssl_Hash algorithm, char[] buffer, int maxlength);

public Extension __ext_curl =
{
    name = "curl",
    file = "curl.ext",
    autoload = 1,
    required = 1,
};
