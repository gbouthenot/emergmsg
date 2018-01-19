/* global base64js */
/* eslint-disable no-console,no-shadow,no-lonely-if */

const iv1 = new Uint8Array([0, 1, 10, 13, 15, 16, 254, 255, 9, 10, 11, 12, 13, 14, 15, 16]);

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
const encryptText = async (plainText, password) => {
  // const iv1 = crypto.getRandomValues(new Uint8Array(16));
  const alg = { name: 'AES-CBC', iv: iv1 };
  const ptUtf8 = new TextEncoder().encode(plainText);
  const pwUtf8 = new TextEncoder().encode(password);
  const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);
  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']);
  return crypto.subtle.encrypt(alg, key, ptUtf8);
};

const decryptText = async (cryptedbytes, password) => {
  const alg = { name: 'AES-CBC', iv: iv1 };
  const pwUtf8 = new TextEncoder().encode(password);
  const pwHash = await crypto.subtle.digest('SHA-256', pwUtf8);
  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']);
  return crypto.subtle.decrypt(alg, key, cryptedbytes);
};


const password = 'mypassword';

const a = encryptText(document.getElementById('clearzone').value, password);
a.then((_) => {
  const crypted64 = base64js.fromByteArray(new Uint8Array(_));
  document.getElementById('cryptzone').value = crypted64;
  const cryptedbytes = base64js.toByteArray(crypted64);
  return decryptText(cryptedbytes, password);
}).then((_) => {
  document.getElementById('decryptzone').value = new TextDecoder().decode(_);
  return _;
});
