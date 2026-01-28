/**
 * Crypto module for ECDH + AES-GCM.
 * 
 * Supports both P-384 (Odyn standard) and secp256k1 (ETH signing key) for encryption.
 * Automatically detects the curve from the enclave's public key.
 */

import * as secp256k1 from '@noble/secp256k1';
import { fetchAttestation, hexToBytes } from './attestation';

export interface EncryptedPayload {
    nonce: string;     // hex-encoded bytes
    public_key: string; // hex-encoded DER public key
    data: string;      // hex-encoded encrypted data
}

export interface AttestationDoc {
    attestation_doc: string;  // Base64-encoded CBOR attestation
    public_key: string;       // hex-encoded DER public key
}

export interface ChatResponse {
    platform: string;
    ai_model: string;
    timestamp: number;
    message: string;
    response: string;
}

// Convert ArrayBuffer to hex string
function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(arr)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Curve types
type CurveType = 'P-384' | 'secp256k1';

// DER SPKI OIDs
const OID_SEC_P384 = '2b81040022';
const OID_SECP256K1 = '2b8104000a';

function detectCurve(keyHex: string): CurveType {
    // Check for DER OIDs first
    if (keyHex.includes(OID_SEC_P384)) {
        return 'P-384';
    }
    if (keyHex.includes(OID_SECP256K1)) {
        return 'secp256k1';
    }

    // Check based on key length (hex string length)
    // DER lengths: P-384 = 240 chars (120 bytes), secp256k1 = 176 chars (88 bytes)
    // Raw lengths: P-384 = 194 chars (97 bytes), secp256k1 = 130 chars (65 bytes)
    const len = keyHex.length;

    if (len === 240 || len === 194) return 'P-384';  // DER or raw P-384
    if (len === 176 || len === 130) return 'secp256k1';  // DER or raw secp256k1

    // Fallback based on approximate length
    if (len > 160) return 'P-384';
    return 'secp256k1';
}

/**
 * Utility to convert DER to raw point, or pass through if already raw.
 * P-384 DER (SPKI) -> 97 bytes raw point
 * P-384 raw -> 97 bytes (pass through)
 * secp256k1 DER (SPKI) -> 65 bytes raw point
 * secp256k1 raw -> 65 bytes (pass through)
 */
function derToRaw(derKey: Uint8Array, curve: CurveType): Uint8Array {
    // P-384
    if (curve === 'P-384') {
        if (derKey.length === 120) {
            // DER SPKI format, strip 23-byte header
            return derKey.slice(23);
        }
        if (derKey.length === 97) {
            // Already raw
            return derKey;
        }
    }

    // secp256k1
    if (curve === 'secp256k1') {
        if (derKey.length === 88) {
            // DER SPKI format, strip 23-byte header
            return derKey.slice(23);
        }
        if (derKey.length === 65) {
            // Already raw
            return derKey;
        }
    }

    // Unknown format, return as-is
    console.warn(`[derToRaw] Unexpected key length ${derKey.length} for curve ${curve}`);
    return derKey;
}

/**
 * Utility to convert raw point back to DER SPKI.
 */
function rawToDer(rawKey: Uint8Array, curve: CurveType): Uint8Array {
    if (curve === 'P-384') {
        const header = hexToBytes('3076301006072a8648ce3d020106082b81040022036200');
        const der = new Uint8Array(header.length + rawKey.length);
        der.set(header, 0);
        der.set(rawKey, header.length);
        return der;
    } else {
        const header = hexToBytes('3056301006072a8648ce3d020106052b8104000a034200');
        const der = new Uint8Array(header.length + rawKey.length);
        der.set(header, 0);
        der.set(rawKey, header.length);
        return der;
    }
}

export class EnclaveClient {
    private enclaveBaseUrl: string = '';
    private isConnected: boolean = false;
    private curve: CurveType = 'P-384';

    // Keys for WebCrypto (P-384)
    private p384KeyPair: CryptoKeyPair | null = null;
    private serverP384Key: CryptoKey | null = null;

    // Keys for secp256k1
    private secpPrivKey: Uint8Array | null = null;
    private secpPubKey: Uint8Array | null = null;
    private serverSecpPubKeyRaw: Uint8Array | null = null;

    get baseUrl() {
        return this.enclaveBaseUrl;
    }

    async connect(baseUrl: string): Promise<AttestationDoc> {
        this.enclaveBaseUrl = baseUrl.replace(/\/$/, '');

        // Fetch attestation first to determine the curve
        const attestation = await this.fetchAttestation();
        this.curve = detectCurve(attestation.public_key);

        console.log(`Detected enclave curve: ${this.curve}`);

        if (this.curve === 'P-384') {
            this.p384KeyPair = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-384' },
                true,
                ['deriveBits']
            );

            const serverPubKeyDer = hexToBytes(attestation.public_key);
            const serverPubKeyRaw = derToRaw(serverPubKeyDer, 'P-384');

            this.serverP384Key = await crypto.subtle.importKey(
                'raw',
                serverPubKeyRaw as any,
                { name: 'ECDH', namedCurve: 'P-384' },
                true,
                []
            );
        } else {
            this.secpPrivKey = secp256k1.utils.randomSecretKey();
            this.secpPubKey = secp256k1.getPublicKey(this.secpPrivKey, false); // uncompressed

            const serverPubKeyDer = hexToBytes(attestation.public_key);
            this.serverSecpPubKeyRaw = derToRaw(serverPubKeyDer, 'secp256k1');

            // Validate the point (v3.0+ uses string for fromHex, and we need to check if it's a valid point)
            try {
                const rawHex = Array.from(this.serverSecpPubKeyRaw).map(b => b.toString(16).padStart(2, '0')).join('');
                secp256k1.Point.fromHex(rawHex);
            } catch (e) {
                console.error('Invalid server public key:', attestation.public_key);
                throw new Error(`Failed to validate server public key: ${e instanceof Error ? e.message : String(e)}`);
            }
        }

        this.isConnected = true;
        return attestation;
    }

    async fetchAttestation(): Promise<AttestationDoc & { parsedAttestation?: string }> {
        try {
            const result = await fetchAttestation(this.enclaveBaseUrl);
            const publicKey = result.attestation_document.public_key || '';

            return {
                attestation_doc: result.raw_doc,
                public_key: publicKey,
                parsedAttestation: JSON.stringify(result)
            };
        } catch (e) {
            console.error('Failed to fetch attestation:', e);
            throw e;
        }
    }

    private async deriveSharedKey(peerPublicKeyDer: string): Promise<CryptoKey> {
        const peerKeyBytes = hexToBytes(peerPublicKeyDer);
        const peerRaw = derToRaw(peerKeyBytes, this.curve);

        let sharedSecret: ArrayBuffer;

        if (this.curve === 'P-384') {
            if (!this.p384KeyPair) throw new Error('P-384 keys not initialized');
            const peerKey = await crypto.subtle.importKey(
                'raw', peerRaw as any, { name: 'ECDH', namedCurve: 'P-384' }, true, []
            );
            sharedSecret = await crypto.subtle.deriveBits(
                { name: 'ECDH', public: peerKey }, (this.p384KeyPair as any).privateKey, 384
            );
        } else {
            if (!this.secpPrivKey) throw new Error('secp256k1 keys not initialized');
            const fullSecret = secp256k1.getSharedSecret(this.secpPrivKey, peerRaw);
            sharedSecret = fullSecret.slice(1, 33).buffer; // Use x-coordinate
        }

        const hkdfKey = await crypto.subtle.importKey(
            'raw', sharedSecret as any, { name: 'HKDF' }, false, ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(0),
                info: new TextEncoder().encode('encryption data')
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async encrypt(plaintext: string): Promise<EncryptedPayload> {
        if (!this.isConnected) throw new Error('Not connected');

        const attestation = await this.fetchAttestation();
        const aesKey = await this.deriveSharedKey(attestation.public_key);

        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce.slice(0, 12) as any }, // Standard AES-GCM expects 12-byte IV
            aesKey,
            new TextEncoder().encode(plaintext)
        );

        let myPubKeyDer: Uint8Array;
        if (this.curve === 'P-384') {
            const raw = await crypto.subtle.exportKey('raw', this.p384KeyPair!.publicKey);
            myPubKeyDer = rawToDer(new Uint8Array(raw), 'P-384');
        } else {
            myPubKeyDer = rawToDer(this.secpPubKey!, 'secp256k1');
        }

        return {
            nonce: bufferToHex(nonce),
            public_key: bufferToHex(myPubKeyDer),
            data: bufferToHex(ciphertext)
        };
    }

    async decrypt(payload: { nonce: string; public_key: string; encrypted_data: string }): Promise<string> {
        if (!this.isConnected) throw new Error('Not connected');

        const aesKey = await this.deriveSharedKey(payload.public_key);
        const nonceBytes = hexToBytes(payload.nonce).slice(0, 12);

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonceBytes as any },
            aesKey,
            hexToBytes(payload.encrypted_data) as any
        );

        return new TextDecoder().decode(plaintext);
    }

    async setApiKey(apiKey: string, platform: string = 'openai'): Promise<any> {
        const payload = JSON.stringify({ api_key: apiKey, platform });
        const encrypted = await this.encrypt(payload);
        const response = await fetch(`${this.enclaveBaseUrl}/set-api-key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(encrypted)
        });
        if (!response.ok) throw new Error('Failed to set API key');
        const result = await response.json();
        const decrypted = await this.decrypt(result.data);
        return JSON.parse(decrypted);
    }

    async chat(message: string, model: string = 'gpt-4'): Promise<any> {
        const payload = JSON.stringify({ message, ai_model: model });
        const encrypted = await this.encrypt(payload);
        const response = await fetch(`${this.enclaveBaseUrl}/talk`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(encrypted)
        });
        if (!response.ok) throw new Error('Chat failed');
        const result = await response.json();
        const decrypted = await this.decrypt(result.data);
        const parsed = JSON.parse(decrypted);

        const attestation = await this.fetchAttestation();
        const health = await this.checkHealth();

        return {
            ...parsed,
            signature: result.sig,
            verificationData: {
                attestation: attestation.attestation_doc,
                publicKey: attestation.public_key,
                ethAddr: health.enclave_address,
                encryptedRequest: JSON.stringify(encrypted),
                decryptedRequest: payload,
                rawResponse: JSON.stringify(result),
                encryptedResponse: JSON.stringify(result.data),
                decryptedResponse: decrypted,
            },
        };
    }

    async checkHealth(): Promise<any> {
        const response = await fetch(`${this.enclaveBaseUrl}/`);
        return response.json();
    }
}

export const enclaveClient = new EnclaveClient();
