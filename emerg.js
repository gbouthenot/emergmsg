/* global base64js LZString */
/* eslint-disable no-console,no-shadow,no-lonely-if */

// concatenate UInt8Arrays
const concatTA = (a, b) => {
  const c = new Uint8Array(a.byteLength + b.byteLength);
  c.set(a);
  c.set(b, a.length);
  return c;
};

// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
const encryptText = async (pt, pw) => {
  const alg = { name: 'AES-CBC', iv: crypto.getRandomValues(new Uint8Array(16)) };
  const ptbin = LZString.compressToUint8Array(pt);
  const pwbin = new TextEncoder().encode(pw);
  const pwHash = await crypto.subtle.digest('SHA-256', pwbin);
  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt']);
  const crypted = await crypto.subtle.encrypt(alg, key, ptbin);
  return concatTA(alg.iv, new Uint8Array(crypted));
};

const decryptText = async (cr, pw) => {
  const alg = { name: 'AES-CBC', iv: cr.slice(0, 16) };
  const pwbin = new TextEncoder().encode(pw);
  const pwHash = await crypto.subtle.digest('SHA-256', pwbin);
  const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt(alg, key, cr.slice(16));
  return LZString.decompressFromUint8Array(new Uint8Array(decrypted));
};


const password = 'mypassword';

const cryptAction = () => {
  const a = encryptText(document.getElementById('clearzone').value, password);
  a.then((_) => {
    const crypted64 = base64js.fromByteArray(new Uint8Array(_));
    let formatted = '';
    for (let i = 0; i < crypted64.length; i += 120) {
      formatted += (i ? '\n' : '') + crypted64.slice(i, i + 120);
    }
    document.getElementById('cryptzone').value = formatted;
  });
};

const decryptAction = () => {
  const crypted64 = document.getElementById('cryptzone').value.replace(/\s/g, '');
  const cryptedbytes = base64js.toByteArray(crypted64);

  const a = decryptText(cryptedbytes, password);
  a.then((_) => {
    document.getElementById('decryptzone').value = _;
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
