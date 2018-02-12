
lz-string for compression:
http://pieroxy.net/blog/pages/lz-string/index.html

base64-js:
https://github.com/beatgammit/base64-js

Crypto API:
https://developer.mozilla.org/en-US/docs/Web/API/Crypto


What it does:
  Crypt:
  - Take the to-be-encrypted string
  - Take the password
  - LZ-compress it (LZString.compressToUint8Array)
  - choose a random IV (crypto.getRandomValues)
  - AES-CBC encrypt the string with the IV and the password (crypto.subtle.encrypt)
  - message = iv . encrypted data
  - base64 message (base64js.fromByteArray)
  - format to 120-char lines

  Decrypt:
  - unformat (remove spaces and line-feed)
  - unbase64 (base64js.toByteArray)
  - extract the iv and the crypted data
  - Take the password
  - AES-CBC decrypt the crypted data with the IV and the password (crypto.subtle.decrypt)
  - LZ-uncompress (LZString.decompressFromUint8Array)



