// Polyfills for React Native
import { Buffer } from 'buffer';
import 'react-native-get-random-values';

// Make Buffer available globally
if (typeof global.Buffer === 'undefined') {
  global.Buffer = Buffer;
}

// Simple crypto polyfill using expo-crypto and noble libraries
import * as Crypto from 'expo-crypto';

if (typeof global.crypto === 'undefined') {
  global.crypto = {
    getRandomValues: (array: any) => {
      const randomBytes = Crypto.getRandomBytes(array.length);
      for (let i = 0; i < array.length; i++) {
        array[i] = randomBytes[i];
      }
      return array;
    },
    // Note: subtle is not fully implemented - SecureAuth will use noble libraries instead
    subtle: undefined as any
  } as any;
}

console.log('🔐 Crypto polyfills loaded, using expo-crypto for random values');

// Ensure TextEncoder and TextDecoder are available
if (typeof global.TextEncoder === 'undefined') {
  (global as any).TextEncoder = class TextEncoder {
    encoding = 'utf-8';
    encode(str: string): Uint8Array {
      return new Uint8Array(Buffer.from(str, 'utf8'));
    }
    encodeInto() { 
      throw new Error('encodeInto not implemented');
    }
  };
}

if (typeof global.TextDecoder === 'undefined') {
  (global as any).TextDecoder = class TextDecoder {
    encoding = 'utf-8';
    fatal = false;
    ignoreBOM = false;
    
    constructor(_label?: string, _options?: any) {
      // Accept parameters but ignore them for simplicity
    }
    
    decode(bytes: Uint8Array): string {
      return Buffer.from(bytes).toString('utf8');
    }
  };
}

export { };

