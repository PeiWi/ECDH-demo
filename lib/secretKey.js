import { 
    _base64ToArrayBuffer,
    _arrayBufferToBase64
 } from "./utils.js";

import { Aes128Gcm, CipherSuite, HkdfSha256 } from "https://esm.sh/@hpke/core@1.2.4";
import { HybridkemX25519Kyber768 } from "https://esm.sh/@hpke/hybridkem-x25519-kyber768@1.2.4";

export default class secretKey {

    #suite = new CipherSuite({
        kem: new HybridkemX25519Kyber768(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
    });

    #extKeyPairCBC
    #extKeyPairGCM
    #extx25519KeyPairCBC
    #extx25519KeyPairGCM
    #aesKeyCBC;
    #aesKeyGCM;
    #iv;
    #environment;
    #deriveKey

    constructor(environment) {
        this.#environment = environment;
    }

    encrypt(plaintext, iv) {
        return crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            this.#aesKeyCBC,
            plaintext
        );
    }

    decryptCBC(ciphertext, iv) {
        return crypto.subtle.decrypt(
            { name: "AES-CBC", iv: iv },
            this.#aesKeyCBC,
            ciphertext
        );
    }

    decryptGCM(ciphertext, iv) {
        return crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            this.#aesKeyGCM,
            ciphertext
        );
    }

    get aesKeyCBC() {
        return this.#aesKeyCBC;
    }
    
    get aesKey() {
        return this.#aesKeyGCM;
    }

    get deriveKey() {
        return this.#deriveKey;
    }

    get suite() {
        return this.#suite;
    }

    set iv(iv) {
        this.#iv = iv;
    }

    get iv() {
        return this.#iv;
    }

    /*------ Key Exchange ------*/
    async keyExchangeCBC(hostPubKeyStr) {
        const hostPubKeyPromise = this.#importECKey(hostPubKeyStr);
        const privateKey = this.#extKeyPairCBC.privateKey;

        return Promise.all([privateKey, hostPubKeyPromise])
            .then(async (keys) => {
                return this.#deriveSecretKeyCBC(keys[0], keys[1])
            })
            .then((derivedKey) => this.#processDerivedKeyCBC(derivedKey))
            .then((secretKey) => this.#aesKeyCBC = secretKey);
    }

    async keyExchangeGCM(hostPubKeyStr) {
        const hostPubKeyPromise = this.#importECKey(hostPubKeyStr);
        const privateKey = this.#extKeyPairGCM.privateKey;

        return Promise.all([privateKey, hostPubKeyPromise])
            .then(async (keys) => {
                return this.#deriveSecretKeyGCM(keys[0], keys[1])
            })
            .then((derivedKey) => this.#processDerivedKeyGCM(derivedKey))
            .then((secretKey) => this.#aesKeyGCM = secretKey);
    }

    async x25519keyExchangeCBC(hostPubKeyStr) {
        const hostPubKeyPromise = this.#importx25519KeyPair(hostPubKeyStr);
        const privateKey = this.#extx25519KeyPairCBC.privateKey.key.buffer;

        return Promise.all([privateKey, hostPubKeyPromise])
            .then(async (keys) => {
                return this.#derivex25519KeyPair(keys[0], keys[1])
            })
            .then((derivedKey) => this.#processDerivedKeyCBC(derivedKey))
            .then((secretKey) => this.#aesKeyCBC = secretKey);
    }

    async x25519keyExchangeGCM(hostPubKeyStr) {
        const hostPubKeyPromise = this.#importx25519KeyPair(hostPubKeyStr);
        const privateKey = this.#extx25519KeyPairGCM.privateKey.key.buffer;

        return Promise.all([privateKey, hostPubKeyPromise])
            .then(async (keys) => {
                return this.#derivex25519KeyPair(keys[0], keys[1])
            })
            .then((derivedKey) => this.#processDerivedKeyGCM(derivedKey))
            .then((secretKey) => this.#aesKeyGCM = secretKey);
    }

    /*------ Derive ------*/
    async deriveKeyValidation(HostDeriveKey) {
        if (HostDeriveKey === this.#deriveKey) {
            return true;
        } 
    }

    async #derivex25519KeyPair(kyberHostPublicKey) {
        const rkp = await suite.kem.deriveKeyPair(kyberHostPublicKey);

        return rkp;
    }

    #deriveSecretKeyCBC(privateKey, publicKey) {
        return crypto.subtle.deriveKey(
          { name: "ECDH", public: publicKey },
          privateKey,
          { name: "AES-CBC", length: 256 },
          true,     // is extractable
          ["encrypt", "decrypt"]
        );
    }

    #deriveSecretKeyGCM(privateKey, publicKey) {
        return crypto.subtle.deriveKey(
          { name: "ECDH", public: publicKey },
          privateKey,
          { name: "AES-GCM", length: 256 },
          true,     // is extractable
          ["encrypt", "decrypt"]
        );
    }

    async #processDerivedKeyCBC(derivedKey) {
        /**
         * On windows, we need to hash the derived key with SHA256
         *  one more time to get the shared key of the native host
         */
        if(this.#environment.os.toLowerCase().includes('win')) {
            const derivedKeyAB = await crypto.subtle.exportKey("raw", derivedKey);
            const hashedDerivedKeyAB = await crypto.subtle.digest('SHA-256', derivedKeyAB);
            const hashedDerivedKeyB64 = _arrayBufferToBase64(hashedDerivedKeyAB);
            this.#deriveKey = hashedDerivedKeyB64;

            const processedDerivedKey = await crypto.subtle.importKey(
                'raw',
                hashedDerivedKeyAB,
                { name: 'AES-CBC', length: 256 },
                false,      // is extractable
                ["encrypt", "decrypt"]
            );

            return processedDerivedKey
            ;
        } else if(this.#environment.os.toLowerCase().includes('mac')) {
            return derivedKey;
        } else throw("Platform not supported");
    }

    async #processDerivedKeyGCM(derivedKey) {
        /**
         * On windows, we need to hash the derived key with SHA256
         *  one more time to get the shared key of the native host
         */
        if(this.#environment.os.toLowerCase().includes('win')) {
            const derivedKeyAB = await crypto.subtle.exportKey("raw", derivedKey);
            const hashedDerivedKeyAB = await crypto.subtle.digest('SHA-256', derivedKeyAB);

            const processedDerivedKey = await crypto.subtle.importKey(
                'raw',
                hashedDerivedKeyAB,
                { name: 'AES-GCM', length: 256 },
                false,      // is extractable
                ["encrypt", "decrypt"]
            );

            return processedDerivedKey
            ;
        } else if(this.#environment.os.toLowerCase().includes('mac')) {
            return derivedKey;
        } else throw("Platform not supported");
    }

    /*------ Import Key ------*/
    #importECKey(publicKeyStr) {
        const publicKeyDer = _base64ToArrayBuffer(publicKeyStr);
        return crypto.subtle.importKey(
          'raw',
          publicKeyDer,
          { name: "ECDH", namedCurve: "P-256" },
          false,    // is extractable
          []
        );
    }

    async #importx25519KeyPair(kyberHostPublicKey) {
        const sharedSecret = await this.#suite.kem.deriveKeyPair(kyberHostPublicKey, this.#extKeyPairCBC.privateKey);
console.log(sharedSecret)
const sharedKey = await this.#suite.kem.deriveSharedKey(this.#extKeyPairCBC.privateKey, kyberHostPublicKey);
console.log(sharedKey)
        const rkp = await suite.kem.importKey("raw", _base64ToArrayBuffer(kyberHostPublicKey));
        console.log(rkp)

        return rkp;
    }

    /*------ Generate Key ------*/
    async getKeyPair() {
        const keyPair = await this.#generateECKeyPair()
        console.log(keyPair)
        this.#extKeyPairCBC = keyPair;
        this.#extKeyPairGCM = keyPair;

        const publicKey = await this.sendPublicKey(keyPair.publicKey);

        return publicKey;
    }

    async getx25519KeyPair() {
        const rkp = await this.#suite.kem.generateKeyPair();

        this.#extx25519KeyPairCBC = rkp;
        this.#extx25519KeyPairGCM = rkp;

        return rkp;
    }


    async sendPublicKey(publicKeyObject) {
        const pubKeyAB = await crypto.subtle.exportKey("spki", publicKeyObject);
        const pubKeyB64 = _arrayBufferToBase64(pubKeyAB);

        return pubKeyB64;
    }

    #generateECKeyPair() {
        return crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          false,    // is extractable
          ["deriveKey"]
        );
    }
}