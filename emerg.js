/* global base64js */
/* eslint-disable no-console,no-shadow,no-lonely-if */

const iv1 = new Uint8Array([0, 1, 10, 13, 15, 16, 254, 255, 9, 10, 11, 12, 13, 14, 15, 16]);

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
const encryptText = async (plainText, password) => {
  // const iv1 = crypto.getRandomValues(new Uint8Array(16));
  const alg = { name: 'AES-CBC', iv: iv1 };
  const ptUtf8 = new TextEncoder().encode(plainText);
  console.log(`bytelength=${ptUtf8.byteLength}`);
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

/*
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
*/

const cryptAction = () => {
  console.log(`clearzone.length=${document.getElementById('clearzone').value.length}`);
  const a = encryptText(document.getElementById('clearzone').value, password);
  a.then((_) => {
    console.log(`crypted.length=${_.byteLength}`);
    const crypted64 = base64js.fromByteArray(new Uint8Array(_));
    console.log(`crypted64.length=${crypted64.length}`);
    let formatted = '';
    for (let i = 0; i < crypted64.length; i += 100) {
      formatted += (i ? '\n' : '') + crypted64.slice(i, i + 100);
    }
    document.getElementById('cryptzone').value = formatted;
  });
};

const decryptAction = () => {
  const crypted64 = document.getElementById('cryptzone').value.replace(/\s/g, '');
  const cryptedbytes = base64js.toByteArray(crypted64);

  const a = decryptText(cryptedbytes, password);
  a.then((_) => {
    document.getElementById('decryptzone').value = new TextDecoder().decode(_);
  });
};

const installHandlers = () => {
  let btn;
  btn = document.querySelector('button[data-action=crypt]');
  btn.addEventListener('click', cryptAction);

  btn = document.querySelector('button[data-action=decrypt]');
  btn.addEventListener('click', decryptAction);
};

installHandlers();
