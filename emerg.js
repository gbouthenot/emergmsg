/* global base64js LZString */
/* eslint-disable no-console,no-bitwise */

// PART TOTP

async function getTotpToken(secret) {
  // OTP code inspired by https://github.com/charlestati/requireris
  // demo: https://charlestati.github.io/requireris/
  function base32decode(str) {
    let curByte = 0; // 12-bit byte
    let dec = 7; // 1st shift is 12-5 bit left
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
      const idx = 'abcdefghijklmnopqrstuvwxyz234567'.indexOf(str[i].toLowerCase());
      if (idx < 0) {
        continue;
      }
      curByte += idx << dec;
      dec -= 5;
      if (dec < 0) {
        bytes.push(curByte >> 4);
        dec += 8;
        curByte = (curByte & 15) << 8;
      }
    }
    // remaining bits are ignored !
    return new Uint8Array(bytes);
  }

  const alg = { name: 'HMAC', hash: { name: 'SHA-1' } };
  const secretU8A = base32decode(secret);

  const key = await crypto.subtle.importKey('raw', secretU8A, alg, true, ['sign', 'verify']);

  let n = Math.floor(Date.now() / 1000 / 30);
  const b = new Uint8Array(8);
  for (let i = 7; i; n >>= 8, --i) {
    b[i] = n & 0xff;
  }
  const sig = await this.crypto.subtle.sign({ name: 'HMAC' }, key, b);
  const s = new Uint8Array(sig);
  let o = s[s.length - 1] & 0xf;
  const tot = ((s[o++] & 0x7f) << 24) | ((s[o++] & 0xff) << 16) | ((s[o++] & 0xff) << 8) | (s[o] & 0xff);
  const res = (tot % 1000000).toString();
  return `000000${res}`.substring(res.length);
}

const otpChangeAction = async (a) => {
  const secret = document.querySelector('input#otpsec').value.trim();
  const cl = document.querySelector('#otpvis').classList;
  if (secret.length < 4) {
    cl.add('hidden');
    return;
  }
  const token = await getTotpToken(secret);
  document.querySelector('#otptok').innerHTML = token;
  cl.remove('hidden');
};

// call itself at sec boundary
const otpval = document.querySelector('#otpval');
const otpTimerInit = () => {
  const time = Date.now() / 1000;
  const frac = time - Math.floor(time);
  let per = time / 30;
  per = 30 - (30 * (per - Math.floor(per)));
  if (per > 29) {
    otpChangeAction();
  }
  otpval.innerHTML = `${Math.round(per)}s`;

  setTimeout(otpTimerInit, 1000 - (frac * 1000));
};

otpTimerInit();

// PART CRYPT / DECRYPT

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


const cryptAction = () => {
  const clear = document.getElementById('clearzone').value;
  const a = encryptText(clear, document.getElementById('password').value);
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

  const a = decryptText(cryptedbytes, document.getElementById('password').value);
  a.then((_) => {
    document.getElementById('clearzone').value = _;
  });
};

const installHandlers = () => {
  let btn;
  btn = document.querySelector('button[data-action=crypt]');
  btn.addEventListener('click', cryptAction);

  btn = document.querySelector('button[data-action=decrypt]');
  btn.addEventListener('click', decryptAction);

  btn = document.querySelector('input#otpsec');
  btn.addEventListener('keyup', otpChangeAction);
};

installHandlers();
