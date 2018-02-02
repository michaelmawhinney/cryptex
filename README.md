<img src="https://img.mikeycomicsinc.com/cryptex_xl.png" width="300px">

# Cryptex: 2-way Authenticated Encryption Class

Cryptex is a simple PHP class that performs 2-way authenticated encryption using XChaCha20 + Poly1305.


# Requirements

* PHP 7.2.0 or newer


# Usage

```
<?php

include "class.cryptex.php";

$plaintext = "You're a certified prince.";
$secret_key = "1-2-3-4-5"; // same combination on my luggage
$salt = random_bytes(32);

try {
    $ciphertext = Cryptex::encrypt($plaintext, $secret_key, $salt);
    $result = Cryptex::decrypt($ciphertext, $secret_key, $salt);
} catch (Exception $e) {
    die($e->getMessage());
}

if (hash_equals($plaintext, $result)) {
    echo "pass";
} else {
    echo "fail";
}

// Output: success

?>
```
