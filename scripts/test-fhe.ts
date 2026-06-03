/**
 * Simple local test script for FHE encryption/decryption.
 */
import { initialize } from "node-seal/dist/index_allows.js";

async function testFHE() {
  console.log("🔐 Testing Microsoft SEAL FHE...");
  
  try {
    const sealInstance = await initialize();
    console.log("✅ Loaded SEAL module");

    // Set up BFV parameters
    const parms = sealInstance.EncryptionParameters(sealInstance.SchemeType.bfv);
    parms.setPolyModulusDegree(2048);
    parms.setCoeffModulus(sealInstance.CoeffModulus.BFVDefault(2048));
    parms.setPlainModulus(sealInstance.PlainModulus.Batching(2048, 20));

    const context = sealInstance.Context(parms, true, sealInstance.SecurityLevel.none);
    console.log("✅ Created SEAL context");

    if (!context.parametersSet()) {
      throw new Error("Parameters not valid");
    }

    // Generate keys
    const keyGenerator = sealInstance.KeyGenerator(context);
    const secretKey = keyGenerator.secretKey();
    const publicKey = keyGenerator.createPublicKey();

    const encryptor = sealInstance.Encryptor(context, publicKey);
    const decryptor = sealInstance.Decryptor(context, secretKey);
    const batchEncoder = sealInstance.BatchEncoder(context);
    console.log("✅ Generated keys and tools");

    // Test with a sample URL
    const testUrl = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
    console.log("\n📄 Testing URL:", testUrl);

    // Encode
    const textEncoder = new TextEncoder();
    const bytes = textEncoder.encode(testUrl);
    const numArray = Array.from(bytes);
    const slotCount = batchEncoder.slotCount();
    const padded = new Array(slotCount).fill(0);
    for (let i = 0; i < numArray.length && i < slotCount; i++) {
      padded[i] = numArray[i];
    }

    const plain = sealInstance.Plaintext();
    batchEncoder.encode(padded, plain);
    console.log("✅ Encoded to plaintext");

    // Encrypt
    const cipher = sealInstance.Ciphertext();
    encryptor.encrypt(plain, cipher);
    const ciphertextBase64 = cipher.save();
    console.log("✅ Encrypted successfully!");

    // Decrypt
    const cipher2 = sealInstance.Ciphertext();
    cipher2.load(context, ciphertextBase64);
    const plain2 = sealInstance.Plaintext();
    decryptor.decrypt(cipher2, plain2);
    console.log("✅ Decrypted successfully!");

    // Decode
    const decodedArray = batchEncoder.decode(plain2);
    let end = decodedArray.length;
    while (end > 0 && decodedArray[end - 1] === 0) end--;
    const resultBytes = new Uint8Array(decodedArray.slice(0, end));
    const resultUrl = new TextDecoder().decode(resultBytes);
    console.log("✅ Decoded to:", resultUrl);

    if (resultUrl === testUrl) {
      console.log("\n🎉 FHE TEST PASSED!");
    } else {
      throw new Error("Decrypted result doesn't match original!");
    }

  } catch (error) {
    console.error("\n❌ FHE TEST FAILED:", error);
    process.exit(1);
  }
}

testFHE();
