const PRIME = (1n << 255n) - 19n;
const A24 = 121665n;

function mod(value: bigint): bigint {
  const result = value % PRIME;
  return result < 0n ? result + PRIME : result;
}

function decodeLittleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  return value;
}

function encodeLittleEndian(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function inverse(value: bigint): bigint {
  let result = 1n;
  let base = mod(value);
  let exponent = PRIME - 2n;
  while (exponent > 0n) {
    if (exponent & 1n) result = mod(result * base);
    base = mod(base * base);
    exponent >>= 1n;
  }
  return result;
}

function x25519(privateBytes: Uint8Array): Uint8Array {
  if (privateBytes.length !== 32) throw new Error("Private key must contain 32 bytes");
  const scalar = new Uint8Array(privateBytes);
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  const k = decodeLittleEndian(scalar);
  const x1 = 9n;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = 9n;
  let z3 = 1n;
  let swap = 0n;
  for (let bit = 254; bit >= 0; bit -= 1) {
    const current = (k >> BigInt(bit)) & 1n;
    swap ^= current;
    if (swap === 1n) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = current;
    const a = mod(x2 + z2);
    const aa = mod(a * a);
    const b = mod(x2 - z2);
    const bb = mod(b * b);
    const e = mod(aa - bb);
    const c = mod(x3 + z3);
    const d = mod(x3 - z3);
    const da = mod(d * a);
    const cb = mod(c * b);
    x3 = mod((da + cb) ** 2n);
    z3 = mod(x1 * mod((da - cb) ** 2n));
    x2 = mod(aa * bb);
    z2 = mod(e * mod(aa + A24 * e));
  }
  if (swap === 1n) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }
  return encodeLittleEndian(mod(x2 * inverse(z2)));
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(value.trim());
  } catch {
    throw new Error("Private key is not valid base64");
  }
  if (binary.length !== 32) throw new Error("Private key must contain 32 bytes");
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

export function generateKeyPair(): KeyPair {
  const privateBytes = crypto.getRandomValues(new Uint8Array(32));
  return {
    privateKey: toBase64(privateBytes),
    publicKey: toBase64(x25519(privateBytes)),
  };
}

export function derivePublicKey(privateKey: string): string {
  return toBase64(x25519(fromBase64(privateKey)));
}
