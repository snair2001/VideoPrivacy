/**
 * lib/encryption.ts
 *
 * Microsoft SEAL (FHE) encryption utilities for PrivateStream Arbitrum.
 *
 * Implementation details:
 *   - SEAL BFV scheme for encryption (good for integer/byte data)
 *   - Server-side key management
 *   - Decryption happens exclusively inside server-side API routes
 *   - Encrypted ciphertext stored on IPFS
 *
 * SECURITY: This module must ONLY be imported in server-side code.
 *           Never import in client components or pages.
 */

import Seal from "node-seal";

// Cached SEAL context and keys (initialized once on server startup)
let sealInstance: any = null;
let context: any = null;
let keyGenerator: any = null;
let publicKey: any = null;
let secretKey: any = null;
let encryptor: any = null;
let decryptor: any = null;

/**
 * Initialize SEAL context and keys.
 * Must be called before any encryption/decryption operations.
 */
async function initSeal(): Promise<void> {
  if (sealInstance) return;

  console.log("Initializing Microsoft SEAL (FHE)...");
  sealInstance = await Seal();

  // Set up BFV encryption parameters (balanced security/performance)
  const parms = sealInstance.EncryptionParameters(
    sealInstance.SchemeType.bfv
  );
  parms.setPolyModulusDegree(4096);
  parms.setCoeffModulus(
    sealInstance.CoeffModulus.BFVDefault(4096)
  );
  parms.setPlainModulus(
    sealInstance.PlainModulus.Batching(4096, 20)
  );

  // Create SEAL context
  context = sealInstance.Context(parms, true, sealInstance.SecurityLevel.tc128);

  // Generate keys
  keyGenerator = sealInstance.KeyGenerator(context);
  publicKey = keyGenerator.createPublicKey();
  secretKey = keyGenerator.secretKey();

  // Create encryptor and decryptor
  encryptor = sealInstance.Encryptor(context, publicKey);
  decryptor = sealInstance.Decryptor(context, secretKey);

  console.log("Microsoft SEAL (FHE) initialized successfully!");
}

/**
 * Encrypts a plaintext string using Microsoft SEAL FHE.
 * @param plaintext - The string to encrypt
 * @returns Encrypted payload as a base64 string (serializable for IPFS)
 */
export async function encryptText(plaintext: string): Promise<string> {
  await initSeal();
  if (!sealInstance) throw new Error("SEAL not initialized");

  // Encode the plaintext string as bytes, then into a SEAL Plaintext
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);

  // Convert bytes to an array of numbers (for SEAL)
  const plaintextArray = Array.from(plaintextBytes);

  // Create a Plaintext and encode the array into it
  const plaintextPt = sealInstance.Plaintext();
  const batchEncoder = sealInstance.BatchEncoder(context);
  batchEncoder.encode(plaintextArray, plaintextPt);

  // Encrypt the Plaintext to a Ciphertext
  const ciphertext = sealInstance.Ciphertext();
  encryptor.encrypt(plaintextPt, ciphertext);

  // Serialize Ciphertext to base64
  const ciphertextBase64 = ciphertext.save();
  return ciphertextBase64;
}

/**
 * Decrypts a SEAL-encrypted payload.
 * @param ciphertextBase64 - Encrypted payload base64 string from encryptText()
 * @returns Decrypted plaintext string
 */
export async function decryptText(ciphertextBase64: string): Promise<string> {
  await initSeal();
  if (!sealInstance) throw new Error("SEAL not initialized");

  // Deserialize base64 back to Ciphertext
  const ciphertext = sealInstance.Ciphertext();
  ciphertext.load(context, ciphertextBase64);

  // Decrypt Ciphertext to Plaintext
  const plaintextPt = sealInstance.Plaintext();
  decryptor.decrypt(ciphertext, plaintextPt);

  // Decode Plaintext back to number array
  const batchEncoder = sealInstance.BatchEncoder(context);
  const plaintextArray = batchEncoder.decode(plaintextPt);

  // Convert number array back to a string (truncate null bytes)
  const plaintextBytes = new Uint8Array(
    plaintextArray.filter((byte: number) => byte !== 0)
  );
  const decoder = new TextDecoder();
  return decoder.decode(plaintextBytes);
}

/**
 * Placeholder for key generation (for future key management).
 * Currently keys are generated in initSeal().
 */
export async function generateMasterKey(): Promise<{
  publicKey: string;
  secretKey: string;
}> {
  await initSeal();
  if (!sealInstance) throw new Error("SEAL not initialized");

  return {
    publicKey: publicKey.save(),
    secretKey: secretKey.save(),
  };
}
