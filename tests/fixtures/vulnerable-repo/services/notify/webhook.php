<?php
// partner webhook signing (v1) — HMAC-SHA1
function sign_v1(string $body, string $secret): string {
    return hash_hmac('sha1', $body, $secret);
}

// legacy payload encryption — AES-128 in ECB
function encrypt_legacy(string $data, string $key): string {
    return openssl_encrypt($data, 'aes-128-ecb', $key, OPENSSL_RAW_DATA);
}

// request id
function request_id(): string {
    return md5(uniqid((string) mt_rand(), true));
}
