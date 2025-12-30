// Verify base58 encoding independently
import { createHash } from 'node:crypto';
import { b58encode, encode, decode } from './src/encoding/base58.js';

// The raw 78-byte extended key data that should encode to the expected xprv
const rawHex = '0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35';
const rawBuffer = Buffer.from(rawHex, 'hex');

console.log('Raw data (78 bytes):', rawBuffer.length);
console.log('Raw hex:', rawBuffer.toString('hex'));

// Calculate checksum manually
function doubleHash256(data) {
    return createHash('sha256').update(createHash('sha256').update(data).digest()).digest();
}

const checksum = doubleHash256(rawBuffer).slice(0, 4);
console.log('Checksum:', checksum.toString('hex'));

// Full data with checksum (82 bytes)
const fullData = Buffer.concat([rawBuffer, checksum]);
console.log('Full data with checksum (82 bytes):', fullData.length);
console.log('Full hex:', fullData.toString('hex'));

// Encode using our function
const encoded = b58encode(rawBuffer);
console.log('\nOur b58encode result:', encoded);
console.log('Expected result:      xprv9s21ZrQH143K3GJpoapnV8SFfuZcESnSgMVMeLxe1tLnUDQSPSMEY4vu4BvU9tgb1yBL7U2tWVmtHvHkhFpNQvkCfwDckKPLSDzyiHr8rWt');

// Let's check what the expected xprv decodes to
console.log('\n=== Checking what expected xprv should decode to ===');

// The expected xprv - what raw bytes does it represent?
// Let's manually decode using an online tool's expected output
// From BIP32 spec, the expected raw bytes for test vector 1 master key should be:
// Version: 0488ade4
// Depth: 00  
// Parent FP: 00000000
// Child Index: 00000000
// Chain Code: 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
// Key: 00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35

// This matches our raw data exactly! So the issue must be in base58 encoding
// Let me test with a known simple example

console.log('\n=== Testing with simple example ===');
const testData = Buffer.from([0x00, 0x01, 0x02, 0x03]);
const testEncoded = encode(testData);
console.log('encode([0,1,2,3]):', testEncoded);
// Expected: should start with '1' for leading zero, then base58 of 0x010203

// Test decode/encode round trip
const testDecoded = decode(testEncoded);
console.log('Round trip:', testDecoded.toString('hex'));
console.log('Match:', testData.equals(testDecoded));

// Now let's try to decode the expected xprv using a different method
console.log('\n=== Attempting raw decoding of expected xprv ===');
const expectedXprv = 'xprv9s21ZrQH143K3GJpoapnV8SFfuZcESnSgMVMeLxe1tLnUDQSPSMEY4vu4BvU9tgb1yBL7U2tWVmtHvHkhFpNQvkCfwDckKPLSDzyiHr8rWt';
const expectedBytes = decode(expectedXprv);  // raw decode without checksum verification
console.log('Expected xprv decodes to (hex):', expectedBytes.toString('hex'));
console.log('Length:', expectedBytes.length, 'bytes');

console.log('\n=== Final comparison ===');
console.log('Our raw + checksum:', fullData.toString('hex'));
