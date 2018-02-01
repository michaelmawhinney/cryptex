**Cryptex** is a simple PHP class that performs 2-way authenticated (secret-key) encryption with associated data using XChaCha20 + Poly1305

# Requirements

* PHP 7.2 or newer


# Basic Example

```
<?php

include "class.cryptex.php";

$plaintext = "hello world!";
$secretkey = "12345";
$saltvalue = random_bytes(32);

$encrypted = Cryptex::encrypt($plaintext, $secretkey, $saltvalue);
$decrypted = Cryptex::decrypt($encrypted, $secretkey, $saltvalue);

if (hash_equals($plaintext, $decrypted)) {
    echo "success";
} else {
    echo "failure";
}

// Output: success

?>
```
