import {
    _base64ToArrayBuffer,
    _arrayBufferToBase64,
    getEnvironmentInfo,
    createMd5Hash
} from "./lib/utils.js";

import { $serverAPI } from "./src/serverAPI.js";
import secretKey from "./lib/secretKey.js";

let iv;
const environment = await getEnvironmentInfo();
const SecretKey = new secretKey(environment);


// Derive API
const derivePublicKey = await SecretKey.getKeyPair();
const deriveResult = await $serverAPI.derive(derivePublicKey);
console.log(deriveResult)

const deriveHost = {
    deriveKey: deriveResult.derivedKey,
    publicKey: deriveResult.truncateSubjectPublicKeyInfo,
    originalMessages: deriveResult.originalMessages
}

await SecretKey.keyExchangeCBC(deriveHost.publicKey);
await SecretKey.keyExchangeGCM(deriveHost.publicKey);

const derivedKeyB64 = SecretKey.deriveKey;
const validation = await SecretKey.deriveKeyValidation(deriveHost.deriveKey);
console.log("Derive key validation: ", validation);


// Kyber API
const kyberKeyPair = await SecretKey.getx25519KeyPair();
const sender = await SecretKey.suite.createSenderContext({
    recipientPublicKey: kyberKeyPair.publicKey,
  });

const kyberPubkeyB64 = _arrayBufferToBase64(kyberKeyPair.publicKey.key);

const kyberResult = await $serverAPI.kyber(kyberPubkeyB64);
console.log("kyberResult: ", kyberResult);

const kyberHost = {
    deriveKey: kyberResult.derivedKey,
    publicKey: kyberResult.truncateSubjectPublicKeyInfo,
    originalMessages: kyberResult.originalMessages
}

// let x25519CBC = await SecretKey.x25519keyExchangeCBC(kyberHost.publicKey);
// let x25519GCM = await SecretKey.x25519keyExchangeGCM(kyberHost.publicKey);
// console.log(x25519CBC, x25519GCM)
// const kyberDerivedKeyB64 = SecretKey.deriveKey;
// console.log(kyberDerivedKeyB64)
// const kyberValidation = await SecretKey.deriveKeyValidation(kyberHostderiveKey);
// console.log(kyberValidation)


// Derive API
async function decryptCBCmessage() {
    iv = createMd5Hash(derivedKeyB64)

    const cipher = _base64ToArrayBuffer(deriveResult.messages[0].value);
    const decryptCBCData = await SecretKey.decryptCBC(cipher, iv)
    const decryptCBCDataB64 = new TextDecoder().decode(decryptCBCData);
    console.log("Decrypt CBC Data: ", decryptCBCDataB64);
}

async function decryptGCMmessage() {
    iv = createMd5Hash(derivedKeyB64);
    iv = iv.slice(0, 12);

    const cipher = _base64ToArrayBuffer(deriveResult.messages[1].value);
    const decryptGCMData = await SecretKey.decryptGCM(cipher, iv);
    const decryptGCMDataRes = new TextDecoder().decode(decryptGCMData);
    console.log("Decrypt GCM Data: ", decryptGCMDataRes);
}

async function encryptMessage() {
    iv = createMd5Hash(derivedKeyB64);

    const data = deriveHost.originalMessages;
    const dataBuffer = new TextEncoder().encode(data);
    const encryptedData = await SecretKey.encrypt(dataBuffer, iv);
    const encryptedDataB64 = _arrayBufferToBase64(encryptedData);

    console.log("Encrypt derive API's CBC original message in Base64: ", encryptedDataB64);
}


// Kyber API
async function kyberdecryptCBCmessage() {
    iv = createMd5Hash(derivedKeyB64)

    const cipher = _base64ToArrayBuffer(kyberResult.messages[0].value);
    const decryptCBCData = await SecretKey.decryptCBC(cipher, iv)
    const decryptCBCDataB64 = _arrayBufferToBase64(decryptCBCData);
    console.log("Decrypt CBC Data in Base64: ", decryptCBCDataB64);
}

async function kyberdecryptGCMmessage() {
    iv = createMd5Hash(derivedKeyB64);
    iv = iv.slice(0, 12);

    const cipher = _base64ToArrayBuffer(kyberResult.messages[1].value);
    const decryptGCMData = await SecretKey.decryptGCM(cipher, iv);
    const decryptGCMDataB64 = _arrayBufferToBase64(decryptGCMData);
    console.log("Decrypt GCM Data in Base64: ", decryptGCMDataB64);
}

async function kyberencryptMessage() {

    // Decrypt
    const data = kyberHost.originalMessages;
    const dataBuffer = await sender.seal(_base64ToArrayBuffer(kyberResult.messages[0].value));

    const Derecipient = await SecretKey.suite.createRecipientContext({
        recipientKey: kyberKeyPair.privateKey,
        enc: sender.enc,
      });

    const decryptedData = await Derecipient.open(_base64ToArrayBuffer(kyberResult.messages[0].value));
    console.log(decryptedData)
    const decryptedDataB64 = new TextDecoder().decode(decryptedData);

    console.log("Decrypt original message in Base64: ", decryptedDataB64)


    // Encrypt

    const message1Buffer = await sender.seal(new TextEncoder().encode(data));
    const message2Buffer = await sender.seal(_base64ToArrayBuffer(kyberResult.messages[1].value));

    console.log("Encrypt original message 1 in Base64: ", _arrayBufferToBase64(message1Buffer));
    console.log("Encrypt original message 2 in Base64: ", _arrayBufferToBase64(message2Buffer))
}




window.decryptCBCmessage = decryptCBCmessage;
window.decryptGCMmessage = decryptGCMmessage;
window.encryptMessage = encryptMessage;
window.kyberencryptMessage = kyberencryptMessage;

