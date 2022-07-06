/* global base64js LZString  */

const crypto = window.crypto
const subtle = window.crypto.subtle

// PART TOTP
class B32 {
  constructor (alphabet) {
    this.alpha = alphabet || 'abcdefghijklmnopqrstuvwxyz234567'
  }

  /**
   * Decode a base32-encoded string to binary
   * @param {string} str non case-sentitive, can by splitted by charcters in " -/"
   * @returns Uint8Array
   */
  b32decode (str) {
    let curByte = 0 // 12-bit byte
    let dec = 7 // 1st shift is 12-5 bit left
    const bytes = []
    for (let i = 0; i < str.length; i++) {
      const idx = this.alpha.indexOf(str[i].toLowerCase())
      if (idx < 0) {
        if (' -/\n'.indexOf(str[i]) >= 0) {
          continue
        } else {
          // throw new Error('base32decode: Invalid char :', str[i])
          continue
        }
      }
      curByte += idx << dec
      dec -= 5
      if (dec < 0 || i === str.length - 1) {
        bytes.push(curByte >> 4)
        dec += 8
        curByte = (curByte & 15) << 8
      }
    }
    return new Uint8Array(bytes)
  }

  /**
   * pad with 0 as low
   * Ex: 0xff -> '74'
   * @param {Uint8Array} input
   * @returns String
   */
  b32encode (input) {
    let output = ''
    for (let bitnumber = 0, curByte = 0; bitnumber < input.length << 3; bitnumber++) {
      curByte |= (input[bitnumber >> 3] & (128 >> (bitnumber % 8))) >> (7 - (bitnumber % 8)) << (4 - (bitnumber % 5))
      if (((bitnumber + 1) === input.length << 3) || ((bitnumber !== 0) && (bitnumber % 5 === 4))) {
        output += this.alpha[curByte]
        curByte = 0
      }
    }
    return output
  }

  autotest () {
    const seed = new Uint8Array([0x64, 0x32, 0x1f, 0x37, 0x48, 0x59, 0x6a])
    if (!(
      (this.b32encode(seed) === 'mqzb6n2ilfva') &&
      (this.b32decode(this.b32encode(seed)).toString() === seed.toString()) &&
      (this.b32decode('777777').toString() === this.b32decode('77 77/7-7').toString()) &&
      (this.b32decode('777777h').toString() !== this.b32decode('777777i').toString()) &&
      (this.b32encode(new Uint8Array([255, 255, 255, 252])) === '777777a')
    )) { throw new Error('autotest: base32 error') }
  }
}

class Totp {
  async getTotpToken (secret, date) {
    // OTP code inspired by https://github.com/charlestati/requireris
    // demo: https://charlestati.github.io/requireris/
    const key = await subtle.importKey('raw', secret, { name: 'HMAC', hash: { name: 'SHA-1' } }, true, ['sign', 'verify'])
    date ||= new Date()
    let n = Math.floor(date.getTime() / 1000 / 30)
    const b = new Uint8Array(8)
    for (let i = 7; i; n >>= 8, --i) {
      b[i] = n & 0xff
    }
    const sig = await subtle.sign({ name: 'HMAC' }, key, b)
    const s = new Uint8Array(sig)
    let o = s[s.length - 1] & 0xf
    const tot = ((s[o++] & 0x7f) << 24) | ((s[o++] & 0xff) << 16) | ((s[o++] & 0xff) << 8) | (s[o] & 0xff)
    const res = (tot % 1000000).toString()
    return `00000${res}`.slice(-6)
  }

  /**
   * return a 6-digit string
   * @param {String} serial ie:'000123456789'
   * @param {Uint8Array} seed
   * @param {Date} date javascript date object (UTC)
   * @returns {String} securid token
   */
  async getStoken (serial, seed, date) {
    async function keyFromTimeCrypt (bytes, secret, keybuffer) {
      const key = new Uint8Array(keybuffer)
      key[0] = 0xaa; key[1] = 0xaa; key[2] = 0xaa; key[3] = 0xaa; key[4] = 0xaa; key[5] = 0xaa; key[6] = 0xaa; key[7] = 0xaa
      for (let i = 0; i < bytes; i++) {
        key[i] = bcdTime[i]
      }
      key[12] = 0xbb; key[13] = 0xbb; key[14] = 0xbb; key[15] = 0xbb
      for (let i = 4; i < 12; i += 2) { /* write BCD-encoded partial serial number */
        key[i / 2 + 6] = ((serial[i] - '0') << 4) | (serial[i + 1] - '0')
      }
      const cryptkey = await subtle.importKey('raw', secret, { name: 'AES-CBC', length: 128 }, true, ['encrypt'])
      const crypted = await subtle.encrypt({ name: 'AES-CBC', length: 128, iv: new Uint8Array(16) }, cryptkey, keybuffer)
      return crypted.slice(0, 16)
    }

    date ||= new Date()
    let [key0, key1] = [new ArrayBuffer(16), new ArrayBuffer(16)]
    const [year, month, day, hour, min] = [date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes()]

    // let [ year, month, day, hour, min] = [ 2021,   05,   31,   9,   56 ] // unix time 1622455008 1622447808+2 hours
    const bcdTime = [((year / 1000) << 4) | ((year / 100) % 10), (((year % 100) / 10) << 4) | (year % 10),
      ((month / 10) << 4) | (month % 10), ((day / 10) << 4) | (day % 10),
      ((hour / 10) << 4) | (hour % 10), (((min & 60) / 10) << 4) | ((min & 60) % 10),
      0, 0]
    key0 = await keyFromTimeCrypt(2, seed, key0)
    key1 = await keyFromTimeCrypt(3, key0, key1)
    key0 = await keyFromTimeCrypt(4, key1, key0)
    key1 = await keyFromTimeCrypt(5, key0, key1)
    key0 = await keyFromTimeCrypt(8, key1, key0)
    const [k0, i] = [new Uint8Array(key0), (min & 3) << 2]
    const otpToken = (((k0[i + 0] << 24) | (k0[i + 1] << 16) | (k0[i + 2] << 8) | (k0[i + 3] << 0)) >>> 0) % 1000000
    return `00000${otpToken}`.slice(-6)
  }

  async autotest () {
    const specDate = new Date('2021-05-31T09:56:00.000Z')
    const secret = new Uint8Array([254, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 253])
    if (!(
      (await this.getTotpToken(secret, specDate) === '965020') &&
      (await this.getStoken('000123456789', secret, specDate)) === '086094')
    ) {
      throw new Error('autotest: totp error')
    }
  }
}

class Main {
  async otpChangeAction (a) {
    const secret = document.querySelector('input#otpsec').value.trim()
    const cl = document.querySelector('#otpvis').classList
    let token
    if (secret.length < 4) {
      cl.add('hidden')
      return
    }
    if (secret.indexOf('*') < 0) {
      token = await this.totp.getTotpToken(this.b32.b32decode(secret))
    } else {
      token = await this.totp.getStoken(`00000000000${secret.slice(0, secret.indexOf('*'))}`.slice(-12), this.b32.b32decode(secret.slice(1 + secret.indexOf('*'))))
    }
    document.querySelector('#otptok').innerHTML = token
    cl.remove('hidden')
  }

  otpTimer () {
    const time = Date.now() / 1000
    const frac = time - Math.floor(time)
    let per = time / 30
    per = 30 - (30 * (per - Math.floor(per)))
    if (per > 29) {
      this.otpChangeAction()
    }
    document.querySelector('#otpval').innerHTML = `${Math.round(per)}s`
    // call itself again at sec boundary
    setTimeout(this.otpTimer.bind(this), 1000 - (frac * 1000))
  }

  // PART CRYPT / DECRYPT

  // concatenate UInt8Arrays
  concatTA (a, b) {
    const c = new Uint8Array(a.byteLength + b.byteLength)
    c.set(a)
    c.set(b, a.length)
    return c
  }

  // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
  async encryptText (pt, pw) {
    const alg = { name: 'AES-CBC', iv: crypto.getRandomValues(new Uint8Array(16)) }
    const ptbin = LZString.compressToUint8Array(pt)
    const pwbin = new TextEncoder().encode(pw)
    const pwHash = await crypto.subtle.digest('SHA-256', pwbin)
    const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt'])
    const crypted = await crypto.subtle.encrypt(alg, key, ptbin)
    return this.concatTA(alg.iv, new Uint8Array(crypted))
  }

  async decryptText (cr, pw) {
    const alg = { name: 'AES-CBC', iv: cr.slice(0, 16) }
    const pwbin = new TextEncoder().encode(pw)
    const pwHash = await crypto.subtle.digest('SHA-256', pwbin)
    const key = await crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt'])
    const decrypted = await crypto.subtle.decrypt(alg, key, cr.slice(16))
    return LZString.decompressFromUint8Array(new Uint8Array(decrypted))
  }

  cryptAction () {
    const clear = document.getElementById('clearzone').value
    this.encryptText(clear, document.getElementById('password').value)
      .then((_) => {
        const crypted64 = base64js.fromByteArray(new Uint8Array(_))
        let formatted = ''
        for (let i = 0; i < crypted64.length; i += 120) {
          formatted += (i ? '\n' : '') + crypted64.slice(i, i + 120)
        }
        document.getElementById('cryptzone').value = formatted
      })
      .catch(e => console.log('error: Cannot encrypt:', e))
  }

  decryptAction () {
    const crypted64 = document.getElementById('cryptzone').value.replace(/\s/g, '')
    const cryptedbytes = base64js.toByteArray(crypted64)

    this.decryptText(cryptedbytes, document.getElementById('password').value)
      .then((_) => {
        document.getElementById('clearzone').value = _
      })
      .catch(e => console.log('error: Cannot decrypt:', e))
  }

  installHandlers () {
    this.totp = new Totp()
    this.b32 = new B32()

    let btn
    btn = document.querySelector('button[data-action=crypt]')
    btn.addEventListener('click', this.cryptAction.bind(this))

    btn = document.querySelector('button[data-action=decrypt]')
    btn.addEventListener('click', this.decryptAction.bind(this))

    btn = document.querySelector('input#otpsec')
    btn.addEventListener('keyup', this.otpChangeAction.bind(this))

    this.otpTimer()
  }
}
