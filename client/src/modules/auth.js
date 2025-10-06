// secure-auth.browser.js
// Browser ES module version of SecureAuth + cryptoUtils

// -- Helpers for ArrayBuffer <-> base64 / hex conversions
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  // chunking for large buffers
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bytesToHex(uint8arr) {
  return Array.from(uint8arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToUint8Array(hex) {
  if (hex.length % 2) throw new Error('Invalid hex string');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return out;
}

function stripPem(pem) {
  return pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/\s+/g, '');
}

// -- Shortcuts to browser crypto
const subtle = (typeof window !== 'undefined' && window.crypto && window.crypto.subtle)
  ? window.crypto.subtle
  : (typeof self !== 'undefined' && self.crypto && self.crypto.subtle)
    ? self.crypto.subtle
    : null;

const getRandomValues = (arr) => {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    return window.crypto.getRandomValues(arr);
  }
  if (typeof self !== 'undefined' && self.crypto && self.crypto.getRandomValues) {
    return self.crypto.getRandomValues(arr);
  }
  throw new Error('Secure random not available');
};

// -- Crypto utilities adapted for browser
const cryptoUtils = {
  generateEphemeralKey: async () => {
    if (!subtle) throw new Error('Web Crypto API (subtle) not available');
    return await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
  },

  exportPublicKey: async (key) => {
    if (!subtle) throw new Error('Web Crypto API (subtle) not available');
    const raw = await subtle.exportKey('spki', key); // ArrayBuffer
    const b64 = arrayBufferToBase64(raw);
    // Create PEM-formatted public key (optional; server may expect plain base64)
    const pemBody = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN PUBLIC KEY-----\n${pemBody}\n-----END PUBLIC KEY-----`;
  },

  // Accepts either PEM string or base64 (no headers)
  importPublicKey: async (base64OrPem) => {
    if (!subtle) throw new Error('Web Crypto API (subtle) not available');
    let b64 = base64OrPem;
    if (typeof base64OrPem === 'string' && base64OrPem.includes('BEGIN PUBLIC KEY')) {
      b64 = stripPem(base64OrPem);
    }
    const raw = base64ToArrayBuffer(b64);
    return await subtle.importKey(
      'spki',
      raw,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
  },

  deriveSharedSecret: async (privKey, pubKey) => {
    if (!subtle) throw new Error('Web Crypto API (subtle) not available');
    const sharedBits = await subtle.deriveBits(
      { name: 'ECDH', public: pubKey },
      privKey,
      256
    ); // returns ArrayBuffer of 32 bytes (256 bits)
    // Import as AES-GCM key for encrypt/decrypt
    return await subtle.importKey(
      'raw',
      sharedBits,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  },

  encrypt: async (plain, key) => {
    if (!subtle) throw new Error('Web Crypto API (subtle) not available');
    const enc = new TextEncoder();
    const iv = new Uint8Array(12);
    getRandomValues(iv);
    const encoded = enc.encode(plain);

    const ciphertextWithTag = new Uint8Array(
      await subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded)
    );

    // AES-GCM outputs ciphertext + tag (tag typically 16 bytes)
    const tagLength = 16;
    if (ciphertextWithTag.length < tagLength) {
      throw new Error('Ciphertext too short');
    }
    const ciphertext = ciphertextWithTag.slice(0, -tagLength);
    const tag = ciphertextWithTag.slice(-tagLength);

    return {
      iv: bytesToHex(iv),
      payload: bytesToHex(ciphertext),
      tag: bytesToHex(tag)
    };
  },

  decrypt: async ({ iv, payload, tag }, key) => {
    if (!subtle) throw new Error('Web Crypto API (subtle) not available');
    const ivBytes = hexToUint8Array(iv);
    const payloadBytes = hexToUint8Array(payload);
    const tagBytes = hexToUint8Array(tag);

    const fullCiphertext = new Uint8Array(payloadBytes.length + tagBytes.length);
    fullCiphertext.set(payloadBytes, 0);
    fullCiphertext.set(tagBytes, payloadBytes.length);

    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      key,
      fullCiphertext
    );
    return new TextDecoder().decode(decrypted);
  }
};

// -- SecureAuth class (browser)
class SecureAuth {
  constructor(authServer = 'https://auth.hitboxgames.online') {
    this.authServer = authServer.replace(/\/+$/, ''); // trim trailing slashes
    this.ws = null;
    this.sharedSecret = null;
    this.clientKeys = null;
    this.logs = [];
  }

  log(msg) {
    this.logs.push(msg);
    // Use console[log] safely
    if (typeof console !== 'undefined') console.log(msg);
  }

  async fetchLoginWsUrl(uuid) {
    try {
      const res = await fetch(`${this.authServer}/login/init?uuid=${encodeURIComponent(uuid)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (!data.wsUrl) throw new Error('No wsUrl in response');
      return data.wsUrl;
    } catch (err) {
      this.log(`❗ Failed to get login wsUrl: ${err.message}`);
      throw err;
    }
  }

  async fetchRegisterWsUrl(uuid) {
    try {
      const res = await fetch(`${this.authServer}/register/init?uuid=${encodeURIComponent(uuid)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (!data.wsUrl) throw new Error('No wsUrl in response');
      return data.wsUrl;
    } catch (err) {
      this.log(`❗ Failed to get register wsUrl: ${err.message}`);
      throw err;
    }
  }

  async generateEphemeralKey() {
    return cryptoUtils.generateEphemeralKey();
  }

  async exportPublicKey(key) {
    return cryptoUtils.exportPublicKey(key);
  }

  async importServerKey(base64OrPem) {
    return cryptoUtils.importPublicKey(base64OrPem);
  }

  async deriveSharedSecret(privKey, pubKey) {
    return cryptoUtils.deriveSharedSecret(privKey, pubKey);
  }

  async encrypt(plain, key) {
    return cryptoUtils.encrypt(plain, key);
  }

  async decrypt(obj, key) {
    return cryptoUtils.decrypt(obj, key);
  }

  // Generic connect used by login/register variants
  async _connect(wsUrl, onMessage, onError, onClose, initialLog) {
    try {
      this.clientKeys = await this.generateEphemeralKey();
      const clientPub = await this.exportPublicKey(this.clientKeys.publicKey);

      this.ws = new WebSocket(wsUrl);

      this.ws.addEventListener('open', () => {
        this.log(initialLog || '🔌 Securely Connecting To Server...');
        // send client public key (PEM). server must accept PEM or base64.
        this.ws.send(JSON.stringify({ type: 'client-public-key', key: clientPub }));
      });

      this.ws.addEventListener('message', async (evt) => {
        try {
          // evt.data may be string or Blob. Handle string only (server should send JSON string)
          const dataStr = typeof evt.data === 'string' ? evt.data : await evt.data.text();
          const parsedData = JSON.parse(dataStr);

          if (parsedData.type === 'server-public-key') {
            if (typeof parsedData.serverPubKey !== 'string') {
              this.log('❌ server-public-key missing string');
              return;
            }
            const serverKey = await this.importServerKey(parsedData.serverPubKey);
            this.sharedSecret = await this.deriveSharedSecret(this.clientKeys.privateKey, serverKey);
            this.log('🔑 End-To-End Encryption Works!');
            return;
          }

          // encrypted payload case
          if (parsedData.payload && parsedData.iv && parsedData.tag) {
            if (!this.sharedSecret) {
              this.log('❌ Received encrypted payload but shared secret missing');
              return;
            }
            const decryptedRaw = await this.decrypt(parsedData, this.sharedSecret);
            let decrypted = null;
            try {
              decrypted = JSON.parse(decryptedRaw);
            } catch (e) {
              // return raw string if not JSON
              decrypted = decryptedRaw;
            }
            if (onMessage) onMessage(decrypted);
            return;
          }

          if (parsedData.type === 'error') {
            const sanitizedMessage = typeof parsedData.message === 'string'
              ? parsedData.message.replace(/[\r\n]+/g, ' ')
              : '';
            this.log(`❌ Error: ${sanitizedMessage}`);
            try { this.ws.close(); } catch (_) {}
            return;
          }

          // Fallback: call onMessage with raw parsedData
          if (onMessage) onMessage(parsedData);
        } catch (err) {
          console.error('❌ Failed to handle message:', err);
          this.log('❌ Failed to handle message: ' + (err && err.message ? err.message : String(err)));
        }
      });

      this.ws.addEventListener('error', (err) => {
        this.log('❌ WebSocket error');
        if (onError) onError(err);
      });

      this.ws.addEventListener('close', () => {
        this.log('❌ Server - Portal closed');
        if (onClose) onClose();
      });
    } catch (err) {
      this.log(`❗ WebSocket/E2E setup failed: ${err && err.message ? err.message : String(err)}`);
      throw err;
    }
  }

  async connectWebSocket(uuid, onMessage, onError, onClose) {
    const wsUrl = await this.fetchLoginWsUrl(uuid);
    await this._connect(wsUrl, onMessage, onError, onClose, '🔌 Securely Connecting To Server...');
  }

  async connectForLogin(uuid, onMessage, onError, onClose) {
    const wsUrl = await this.fetchLoginWsUrl(uuid);
    await this._connect(wsUrl, onMessage, onError, onClose, '🔌 Securely Connecting To Login Server...');
  }

  async connectForRegister(uuid, onMessage, onError, onClose) {
    const wsUrl = await this.fetchRegisterWsUrl(uuid);
    await this._connect(wsUrl, onMessage, onError, onClose, '🔌 Securely Connecting To Register Server...');
  }

  async submitLogin(uuid, username, password) {
    if (!this.ws || !this.sharedSecret) {
      this.log('🔒 Shared secret not ready');
      throw new Error('❌ Shared secret not ready');
    }
    const creds = JSON.stringify({ type: 'login', username, password, uuid });
    const encrypted = await this.encrypt(creds, this.sharedSecret);
    this.ws.send(JSON.stringify(encrypted));
    this.log('📤 Attempting login...');
  }

  async submitRegister(uuid, username, password, email = null) {
    if (!this.ws || !this.sharedSecret) {
      this.log('🔒 Shared secret not ready');
      throw new Error('❌ Shared secret not ready');
    }
    const registrationData = { type: 'register', username, password, uuid };
    if (email) registrationData.email = email;
    const creds = JSON.stringify(registrationData);
    const encrypted = await this.encrypt(creds, this.sharedSecret);
    this.ws.send(JSON.stringify(encrypted));
    this.log('📤 Attempting registration...');
  }

  close() {
    if (this.ws) {
      try { this.ws.close(); } catch (_) {}
      this.ws = null;
    }
  }

  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  getLogs() {
    return this.logs.slice();
  }

  clearLogs() {
    this.logs = [];
  }
}

/* For convenience, add named convenience exports dynamically so bundlers pick them up: */
export const generateEphemeralKey = (...args) => cryptoUtils.generateEphemeralKey(...args);
export const exportPublicKey = (...args) => cryptoUtils.exportPublicKey(...args);
export const importPublicKey = (...args) => cryptoUtils.importPublicKey(...args);
export const deriveSharedSecret = (...args) => cryptoUtils.deriveSharedSecret(...args);
export const encrypt = (...args) => cryptoUtils.encrypt(...args);
export const decrypt = (...args) => cryptoUtils.decrypt(...args);
export { SecureAuth };
