/**
 * lib/encryption.ts
 *
 * Microsoft SEAL (FHE) encryption utilities for PrivateStream Arbitrum.
 *
 * SECURITY: This module must ONLY be imported in server-side code.
 */

// Use CommonJS require to bypass package.json exports restrictions
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { initialize } = require('../node_modules/node-seal/dist/index_allows.js');

// Cached SEAL instance (persists between requests in serverless if warm)
let sealInstance: any = null;
let context: any = null;
let secretKey: any = null;
let publicKey: any = null;
let encryptor: any = null;
let decryptor: any = null;
let batchEncoder: any = null;
let isInitialized = false;

async function initSeal(): Promise<void> {
  if (isInitialized && sealInstance) return;

  console.log("🔐 Initializing Microsoft SEAL FHE...");
  try {
    sealInstance = await initialize();
    console.log("✅ Loaded SEAL module");

    // Optimized BFV parameters for Vercel serverless (smaller, faster)
    const parms = sealInstance.EncryptionParameters(sealInstance.SchemeType.bfv);
    parms.setPolyModulusDegree(2048); // Smaller for better serverless performance
    parms.setCoeffModulus(sealInstance.CoeffModulus.BFVDefault(2048));
    parms.setPlainModulus(sealInstance.PlainModulus.Batching(2048, 20));

    // Create context (no security level for speed on testnet)
    context = sealInstance.Context(parms, true, sealInstance.SecurityLevel.none);
    
    if (!context.parametersSet()) {
      throw new Error("SEAL parameters validation failed");
    }
    console.log("✅ Created SEAL context");

    // Generate keys
    const keyGenerator = sealInstance.KeyGenerator(context);
    secretKey = keyGenerator.secretKey();
    publicKey = keyGenerator.createPublicKey();
    console.log("✅ Generated keys");

    // Initialize tools
    encryptor = sealInstance.Encryptor(context, publicKey);
    decryptor = sealInstance.Decryptor(context, secretKey);
    batchEncoder = sealInstance.BatchEncoder(context);
    console.log("✅ Initialized crypto tools");

    isInitialized = true;
    console.log("🎉 SEAL FHE initialized successfully!");
  } catch (error) {
    console.error("❌ SEAL initialization failed:", error);
    throw new Error(`SEAL init failed: ${(error as Error).message}`);
  }
}

export async function encryptText(plaintext: string): Promise<string> {
  try {
    await initSeal();
    
    if (!batchEncoder || !encryptor || !sealInstance) {
      throw new Error("SEAL not properly initialized");
    }

    // Encode string to byte array, then to number array
    const bytes = new TextEncoder().encode(plaintext);
    const numArray = Array.from(bytes);

    // Pad to batch size
    const slotCount = batchEncoder.slotCount();
    const padded = new Array(slotCount).fill(0);
    for (let i = 0; i < numArray.length && i < slotCount; i++) {
      padded[i] = numArray[i];
    }

    // Encode and encrypt
    const plain = sealInstance.Plaintext();
    batchEncoder.encode(padded, plain);

    const cipher = sealInstance.Ciphertext();
    encryptor.encrypt(plain, cipher);

    return cipher.save();
  } catch (error) {
    console.error("❌ FHE encryption failed:", error);
    throw new Error(`Encryption failed: ${(error as Error).message}`);
  }
}

export async function decryptText(ciphertextBase64: string): Promise<string> {
  try {
    await initSeal();
    
    if (!batchEncoder || !decryptor || !sealInstance) {
      throw new Error("SEAL not properly initialized");
    }

    // Deserialize and decrypt
    const cipher = sealInstance.Ciphertext();
    cipher.load(context, ciphertextBase64);

    const plain = sealInstance.Plaintext();
    decryptor.decrypt(cipher, plain);

    // Decode back to string
    const decodedArray = batchEncoder.decode(plain);
    
    // Find actual data end (trim trailing zeros)
    let end = decodedArray.length;
    while (end > 0 && decodedArray[end - 1] === 0) {
      end--;
    }

    const resultBytes = new Uint8Array(decodedArray.slice(0, end));
    return new TextDecoder().decode(resultBytes);
  } catch (error) {
    console.error("❌ FHE decryption failed:", error);
    throw new Error(`Decryption failed: ${(error as Error).message}`);
  }
}
