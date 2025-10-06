import { Buffer } from 'buffer';
import { hashString } from './deviceUtils';
import { secureStorage } from './secureStorage';
// @ts-ignore - runtime import available via package.json dependencies
// We'll use elliptic at runtime to perform ECDH (p256) for broader compatibility
// elliptic is a pure-JS implementation that works on React Native/Expo

type EncryptedData = {
  iv: string;
  payload: string;
  tag: string;
};

type AuthMessage = {
  type?: string;
  status?: string;
  data?: any;
  token?: string;
  [key: string]: any;
};

/**
 * SecureAuth - simplified TypeScript implementation for the app
 * - Uses deviceUtils.hashString to derive a shared secret
 * - Sends a PEM-like client public key (mocked) to satisfy server key-exchange expectations
 * - Encrypts login payload with a deterministic XOR using the derived key (demo-only)
 * - Stores returned token in secureStorage
 */
export class SecureAuth {
  private authServer: string;
  private ws: WebSocket | null = null;
  private sharedKey: Buffer | null = null;
  private ephPriv: Uint8Array | null = null;
  private ephPub: Uint8Array | null = null;
  private aesKeyBytes: Uint8Array | null = null;
  private logs: string[] = [];

  constructor(authServer = 'http://localhost:3001') {
    this.authServer = authServer.replace(/\/+$/, '');
  }

  log(msg: string) {
    this.logs.push(msg);
    console.log('🔐 SecureAuth:', msg);
  }

  isConnected(): boolean {
    return !!this.ws && this.ws.readyState === 1;
  }

  close() {
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }
  }

  getLogs(): string[] {
    return [...this.logs];
  }

  private async fetchLoginWsUrl(uuid: string): Promise<string> {
    const url = `${this.authServer}/login/init?uuid=${encodeURIComponent(uuid)}`;
    this.log(`Fetching login URL from: ${url}`);
    const res = await fetch(url);
    this.log(`Fetch status: ${res.status}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    if (!body.wsUrl) throw new Error('No wsUrl from auth server');
    return body.wsUrl;
  }

  private deriveSharedKey(uuid: string): Promise<Buffer> {
    return new Promise(async (resolve) => {
      try {
        const hex = await hashString(uuid + '-shared');
        // hex is 64 char hex; convert to bytes
        const buf = Buffer.from(hex, 'hex');
        resolve(buf.slice(0, 32));
      } catch (e) {
        // fallback deterministic key
        const fallback = Buffer.from(uuid).slice(0, 32);
        resolve(fallback);
      }
    });
  }

  private makePemFromKey(keyBuf: Buffer): string {
    // Build a proper SubjectPublicKeyInfo (SPKI) DER for P-256 using the uncompressed point
    // Expected keyBuf: uncompressed public key (65 bytes: 0x04 || X(32) || Y(32))
    if (keyBuf.length === 65 && keyBuf[0] === 0x04) {
      // SPKI header for EC public key on prime256v1 (1.2.840.10045.3.1.7)
      const spkiPrefix = Buffer.from([
        0x30, 0x59, // SEQUENCE, length 89
        0x30, 0x13, // SEQUENCE, length 19
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7 (P-256)
        0x03, 0x42, 0x00 // BIT STRING, length 66, no unused bits
      ]);

      const der = Buffer.concat([spkiPrefix, keyBuf]);
      const b64 = der.toString('base64');
      const lines = b64.match(/.{1,64}/g) || [b64];
      return ['-----BEGIN PUBLIC KEY-----', ...lines, '-----END PUBLIC KEY-----'].join('\n');
    }

    // Fallback: wrap whatever bytes we have
    const b64 = keyBuf.toString('base64');
    const lines = b64.match(/.{1,64}/g) || [b64];
    return ['-----BEGIN PUBLIC KEY-----', ...lines, '-----END PUBLIC KEY-----'].join('\n');
  }
  // ECDH keypair helpers (using p256)
  private generateEphemeralKeypair(): { priv: Uint8Array; pub: Uint8Array } {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const EC = require('elliptic').ec;
      const ec = new EC('p256');
      const key = ec.genKeyPair();
      const privHex = key.getPrivate('hex');
      const priv = Buffer.from(privHex, 'hex');
      // uncompressed public key (04 || X || Y)
      // @ts-ignore - encode may be present on the Point
      const pubArr: number[] = key.getPublic().encode('array', false);
      const pub = Uint8Array.from(pubArr);
      return { priv, pub };
    } catch (e) {
      throw new Error('elliptic library is required for ECDH (install with `npm install elliptic` or `bun add elliptic`)');
    }
  }

  // Derive shared secret (raw) from our private key and remote public key
  private deriveSharedSecretRaw = async (priv: Uint8Array, remotePubBytes: Uint8Array): Promise<Uint8Array> => {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const EC = require('elliptic').ec;
      const ec = new EC('p256');

      // If server sent an SPKI DER (or PEM->DER), extract the uncompressed point
      let pubBytes = Buffer.from(remotePubBytes);
      // If this looks like a full ASN.1 SPKI, find the uncompressed point (0x04 + 64 bytes)
      if (pubBytes.length > 65) {
        // search for 0x04 marker where remaining length is 65
        let idx = -1;
        for (let i = 0; i < pubBytes.length; i++) {
          if (pubBytes[i] === 0x04 && pubBytes.length - i === 65) {
            idx = i;
            break;
          }
        }
        if (idx !== -1) {
          pubBytes = pubBytes.slice(idx, idx + 65);
        } else {
          // as a fallback, if BIT STRING header present (0x03 len 0x42 0x00), strip the prefix
          const bsIdx = pubBytes.indexOf(Buffer.from([0x03, 0x42, 0x00]));
          if (bsIdx !== -1 && pubBytes.length >= bsIdx + 3 + 65) {
            pubBytes = pubBytes.slice(bsIdx + 3, bsIdx + 3 + 65);
          }
        }
      }

      const privHex = Buffer.from(priv).toString('hex');
      const remoteHex = Buffer.from(pubBytes).toString('hex');
      const key = ec.keyFromPrivate(privHex, 'hex');
      const other = ec.keyFromPublic(remoteHex, 'hex');
      // derive returns a BN.js instance -> hex (raw shared secret)
      const sharedBN = key.derive(other.getPublic());
      let sharedHex = sharedBN.toString(16);
      if (sharedHex.length % 2) sharedHex = '0' + sharedHex;
      // Return raw shared secret bytes (no extra hashing) to match Node.js ECDH.computeSecret behavior
      let raw = Buffer.from(sharedHex, 'hex');
      // Ensure 32 bytes (pad on the left if necessary)
      if (raw.length < 32) {
        const padded = Buffer.alloc(32);
        raw.copy(padded, 32 - raw.length);
        raw = padded;
      }
      return raw;
    } catch (e) {
      throw new Error('Failed to derive shared secret via elliptic: ' + String(e));
    }
  };

  // AES-GCM encrypt via SubtleCrypto when available, node-forge fallback otherwise.
  private async aesGcmEncrypt(plaintext: string, keyBytes: Uint8Array): Promise<EncryptedData> {
    const subtle = (globalThis as any).crypto?.subtle;
    let iv: Uint8Array | Buffer = null as any;
    try {
      if ((globalThis as any).crypto && typeof (globalThis as any).crypto.getRandomValues === 'function') {
        iv = (globalThis as any).crypto.getRandomValues(new Uint8Array(12));
      }
    } catch (_e) {}
    if (!iv) {
      // Fallback: build 12 bytes from Math.random (not crypto secure but avoids Node stdlib in Expo)
      const arr = new Uint8Array(12);
      for (let i = 0; i < 12; i++) arr[i] = Math.floor(Math.random() * 256);
      iv = arr;
    }

    if (subtle) {
      try {
        const alg = { name: 'AES-GCM', iv };
        const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
        const enc = new TextEncoder().encode(plaintext);
        const cipher = await subtle.encrypt(alg, cryptoKey, enc);
        const cipherBuf = Buffer.from(cipher);
        // AES-GCM appends the auth tag to the ciphertext; split last 16 bytes as tag
        const tagLen = 16;
        const payloadBuf = cipherBuf.slice(0, cipherBuf.length - tagLen);
        const tagBuf = cipherBuf.slice(cipherBuf.length - tagLen);
        this.log('Using SubtleCrypto for AES-GCM encryption');
        return { iv: Buffer.from(iv).toString('hex'), payload: payloadBuf.toString('hex'), tag: tagBuf.toString('hex') };
      } catch (err: any) {
        // If SubtleCrypto fails (e.g., Firefox OperationError), log and fall back to node-forge
        this.log('SubtleCrypto AES-GCM encrypt failed: ' + (err?.name || '') + ': ' + (err?.message || err));
        // continue to node-forge fallback below
      }
    }

    // Fallback to node-forge when SubtleCrypto isn't available (pure-JS, works on RN)
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const forge = require('node-forge');
      const keyBin = forge.util.createBuffer(Buffer.from(keyBytes)).getBytes();
      const ivBin = forge.util.createBuffer(Buffer.from(iv)).getBytes();
      const cipher = forge.cipher.createCipher('AES-GCM', keyBin);
      cipher.start({ iv: ivBin, tagLength: 128 });
      cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
      const finishOk = cipher.finish();
      if (!finishOk) throw new Error('node-forge AES-GCM encryption failed');
      const cipherTextBin = cipher.output.getBytes();
      const tagBin = cipher.mode.tag.getBytes();
      const ctArr = Buffer.from(cipherTextBin, 'binary');
      this.log('Using node-forge for AES-GCM encryption');
      return { iv: Buffer.from(iv).toString('hex'), payload: ctArr.toString('hex'), tag: Buffer.from(tagBin, 'binary').toString('hex') };
    } catch (e) {
      throw new Error('No WebCrypto Subtle available and node-forge AES-GCM fallback failed: ' + String(e));
    }
  }

  // AES-GCM decrypt: accepts EncryptedData (hex or base64) and returns plaintext string
  private async aesGcmDecrypt(enc: EncryptedData, keyBytes: Uint8Array): Promise<string> {
    const subtle = (globalThis as any).crypto?.subtle;
    const hexRegex = /^[0-9a-fA-F]+$/;

    if (subtle) {
      try {
        // Normalize iv and payload/tag into Uint8Array with ciphertext followed by tag (Subtle expects CT||TAG)
        let ivBytes: Uint8Array;
        let combined: Uint8Array;

        if (enc.iv && hexRegex.test(enc.iv)) {
          const ivBuf = Buffer.from(enc.iv, 'hex');
          ivBytes = new Uint8Array(ivBuf);
        } else {
          ivBytes = new Uint8Array(Buffer.from(enc.iv, 'base64'));
        }

        if (enc.payload && enc.tag && hexRegex.test(enc.payload) && hexRegex.test(enc.tag)) {
          const payloadBuf = Buffer.from(enc.payload, 'hex');
          const tagBuf = Buffer.from(enc.tag, 'hex');
          combined = new Uint8Array(payloadBuf.length + tagBuf.length);
          combined.set(payloadBuf, 0);
          combined.set(tagBuf, payloadBuf.length);
        } else if (enc.payload) {
          // assume base64 payload already contains tag or no tag provided
          const payloadBuf = Buffer.from(enc.payload, 'base64');
          combined = new Uint8Array(payloadBuf);
        } else {
          throw new Error('Invalid iv/payload/tag format');
        }

        const alg = { name: 'AES-GCM', iv: ivBytes };
        const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
        const plain = await subtle.decrypt(alg, cryptoKey, combined);
        this.log('Using SubtleCrypto for AES-GCM decryption');
        return new TextDecoder().decode(new Uint8Array(plain));
      } catch (err: any) {
        this.log('SubtleCrypto AES-GCM decrypt failed: ' + (err?.name || '') + ': ' + (err?.message || err));
        // continue to node-forge fallback below
      }
    }

    // node-forge fallback
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const forge = require('node-forge');
      const keyBin = forge.util.createBuffer(Buffer.from(keyBytes)).getBytes();
      const ivBin = forge.util.createBuffer(Buffer.from(enc.iv, 'hex')).getBytes();
      let ctBuf = Buffer.from(enc.payload, 'hex');
      let tagBuf = enc.tag ? Buffer.from(enc.tag, 'hex') : Buffer.alloc(0);
      // If tag is missing but payload contains CT||TAG, split last 16 bytes
      if (tagBuf.length === 0 && ctBuf.length > 16) {
        tagBuf = ctBuf.slice(ctBuf.length - 16);
        ctBuf = ctBuf.slice(0, ctBuf.length - 16);
      }
      const ctBin = ctBuf.toString('binary');
      const tagBin = tagBuf.toString('binary');
      const decipher = forge.cipher.createDecipher('AES-GCM', keyBin);
      decipher.start({ iv: ivBin, tagLength: 128, tag: forge.util.createBuffer(tagBin) });
      decipher.update(forge.util.createBuffer(ctBin, 'binary'));
      const ok = decipher.finish();
      if (!ok) throw new Error('node-forge AES-GCM decryption failed (tag mismatch)');
      const out = decipher.output.getBytes();
      this.log('Using node-forge for AES-GCM decryption');
      return out;
    } catch (e) {
      throw new Error('No WebCrypto Subtle available and node-forge AES-GCM fallback failed: ' + String(e));
    }
  }

  // connectForLogin performs the full handshake and returns the auth token
  async connectForLogin(uuid: string, username?: string, password?: string): Promise<string> {
    this.log(`Starting connectForLogin with UUID: ${uuid}`);
    const wsUrl = await this.fetchLoginWsUrl(uuid);
    this.log(`Got WebSocket URL: ${wsUrl}`);

  // generate ephemeral ECDH keypair for this handshake
  const kp = this.generateEphemeralKeypair();
  this.ephPriv = kp.priv;
  this.ephPub = kp.pub;
  this.log('Generated ephemeral ECDH keypair');

    return new Promise<string>((resolve, reject) => {
      try {
        this.ws = new WebSocket(wsUrl);

        let keySent = false;

        const cleanupAndReject = (err: any) => {
          try { this.close(); } catch {}
          // Normalize to an Error instance to avoid passing native event objects to the caller
          let outErr: Error;
          if (err instanceof Error) outErr = err;
          else if (typeof err === 'string') outErr = new Error(err);
          else {
            try {
              const s = JSON.stringify(err);
              outErr = new Error(s.length > 1000 ? s.slice(0, 1000) + '...' : s);
            } catch (_e) {
              outErr = new Error(String(err));
            }
          }
          reject(outErr);
        };

        this.ws.onopen = () => {
          this.log('WebSocket connected');
          try {
            // send client public key using the server's expected property name 'key'
            // Many servers expect a PEM/ASN.1 SubjectPublicKeyInfo string. Use the helper to build a PEM
            try {
              const pem = this.makePemFromKey(Buffer.from(this.ephPub!));
              const msg = { type: 'client-public-key', key: pem };
              this.ws!.send(JSON.stringify(msg));
              keySent = true;
              this.log('Sent client public key (PEM)');
            } catch (e) {
              // Fallback: send raw base64 if PEM creation fails
              const pubB64 = Buffer.from(this.ephPub!).toString('base64');
              const msg = { type: 'client-public-key', key: pubB64 };
              this.ws!.send(JSON.stringify(msg));
              keySent = true;
              this.log('Sent client public key (base64 fallback)');
            }
          } catch (e) {
            cleanupAndReject(e);
          }
        };

        this.ws.onmessage = async (ev) => {
          try {
            const m: AuthMessage = JSON.parse(ev.data as string);

            // If server says awaiting client public key, we already sent it; wait
            if (m.status === 'awaiting-client-public-key') {
              this.log('Server awaiting client public key');
              return;
            }

            // If server sends a server public key or acknowledges, send login
            if (keySent && (m.type === 'server-public-key' || m.serverPubKey || m.key || m.publicKey)) {
              this.log('Received server public key, deriving shared AES key');
              try {
                const serverKeyB64 = (m.serverPubKey || m.key || m.publicKey) as string;
                const serverPub = Buffer.from(serverKeyB64, 'base64');
                const shared = await this.deriveSharedSecretRaw(this.ephPriv!, new Uint8Array(serverPub));
                this.aesKeyBytes = shared; // already a sha256 hash (32 bytes)

                // encrypt login payload with AES-GCM (include username/password when provided)
                const payloadObj: any = { type: 'login', uuid };
                if (username) payloadObj.username = username;
                if (password) payloadObj.password = password;
                const payload = JSON.stringify(payloadObj);
                // Debug: log plaintext being encrypted so server/client can be compared (development only)
                if (!this.aesKeyBytes) throw new Error('Derived AES key missing');
                const enc = await this.aesGcmEncrypt(payload, this.aesKeyBytes);
                // Debug: log small preview of the encrypted fields (lengths + first bytes) to help diagnose auth tag failures
                try {
                  const preview = `iv=${enc.iv.slice(0, 12)}(${enc.iv.length}), payload=${enc.payload.slice(0, 12)}(${enc.payload.length}), tag=${enc.tag.slice(0, 12)}(${enc.tag.length})`;
                } catch (e) {
                  this.log('Failed to build auth preview: ' + String(e));
                }
                // send iv/payload/tag at top-level to match server expectations
                const authMsg = { type: 'login', iv: enc.iv, payload: enc.payload, tag: enc.tag };
                this.ws!.send(JSON.stringify(authMsg));
              } catch (e) {
                this.log(`Key-exchange/encrypt failed: ${e}`);
                cleanupAndReject(e);
              }
              return;
            }
            // If server sends an encrypted payload (payload/iv/tag at top-level), try decrypting
            if ((m.payload && m.iv) && this.aesKeyBytes) {
              try {
                // server uses hex in original implementation - try both hex and base64
                const enc: EncryptedData = { iv: m.iv, payload: m.payload, tag: m.tag };
                // Server uses hex for iv/payload/tag; pass through directly to decrypt (aesGcmDecrypt handles hex)
                const decrypted = await this.aesGcmDecrypt(enc, this.aesKeyBytes!);
                const parsed = JSON.parse(decrypted);
                const token = parsed.token || parsed.jwt || m.token || m.jwt;
                if (token) {
                  await secureStorage.setItemAsync('auth_token', token);
                  this.log('Stored token in secure storage');
                  resolve(token);
                  this.close();
                  return;
                }
              } catch (e) {
                this.log(`Decryption/parsing failed: ${e}`);
              }
            }

            // If we receive auth_response or direct token fields, return token
            if (m.type === 'auth_response' || m.type === 'auth_result' || m.token || m.jwt) {
              const token = m.token || m.jwt;
              if (token) {
                await secureStorage.setItemAsync('auth_token', token);
                this.log('Stored token in secure storage');
                resolve(token);
                this.close();
                return;
              }

              if (m.type === 'error' || m.error) {
                cleanupAndReject(new Error(m.error || m.message || 'Authentication failed'));
                return;
              }
            }
          } catch (err) {
            cleanupAndReject(err);
          }
        };

        this.ws.onerror = (err) => {
          // WebSocket error events are often non-Error objects; wrap into Error with helpful message
          try {
            const msg = (err && (err as any).message) ? (err as any).message : 'WebSocket error';
            cleanupAndReject(new Error(msg));
          } catch (e) {
            cleanupAndReject(new Error('WebSocket error'));
          }
        };

        this.ws.onclose = () => {
          this.log('WebSocket closed');
        };
      } catch (err) {
        reject(err);
      }
    });
  }

  // For compatibility - registration will use the same flow here (demo)
  async connectForRegister(uuid: string): Promise<string> {
    return this.connectForLogin(uuid);
  }
}

export default SecureAuth;