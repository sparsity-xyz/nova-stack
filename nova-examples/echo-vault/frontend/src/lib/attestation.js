/**
 * Attestation fetching and parsing utilities.
 * 
 * Ported from secured-chat-bot to handle AWS Nitro Enclave attestation documents.
 */

/**
 * Parse user_data field which may contain eth_addr.
 */
export function parseUserData(userData) {
    if (!userData) return { isJson: false };

    try {
        const parsed = typeof userData === 'string' ? JSON.parse(userData) : userData;
        return {
            ethAddr: parsed.eth_addr || parsed.ethAddr,
            isJson: true,
            jsonData: parsed
        };
    } catch (e) {
        // Check for hex-encoded user data with eth_addr
        if (typeof userData === 'string' && userData.startsWith('0x')) {
            return { ethAddr: userData, isJson: false };
        }
        return { isJson: false };
    }
}

/**
 * Convert bytes to hexadecimal string.
 */
export const bytesToHex = (bytes) => {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return Array.from(arr)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
};

/**
 * Convert raw P-384 public key to DER/SPKI format.
 */
function rawToDer(rawKey) {
    const P384_DER_HEADER = new Uint8Array([
        0x30, 0x76,  // SEQUENCE, length 118
        0x30, 0x10,  // SEQUENCE, length 16
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  // OID 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,              // OID 1.3.132.0.34 (secp384r1)
        0x03, 0x62, 0x00  // BITSTRING, length 98, no unused bits
    ]);

    if (rawKey.length === 120 && rawKey[0] === 0x30) {
        return rawKey;
    }

    if (rawKey.length !== 97) {
        console.warn(`[rawToDer] Unexpected key length ${rawKey.length}, returning as-is`);
        return rawKey;
    }

    const derKey = new Uint8Array(P384_DER_HEADER.length + rawKey.length);
    derKey.set(P384_DER_HEADER, 0);
    derKey.set(rawKey, P384_DER_HEADER.length);
    return derKey;
}

/**
 * Convert raw bytes to PEM-formatted string.
 */
function bytesToPem(label, data) {
    const b64 = btoa(new Uint8Array(data).reduce((data, byte) => data + String.fromCharCode(byte), ''));
    const wrapped = b64.match(/.{1,64}/g)?.join('\n') || '';
    return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

/**
 * Check if a string contains only printable ASCII.
 */
function isPrintableAscii(text) {
    for (let i = 0; i < text.length; i++) {
        const charCode = text.charCodeAt(i);
        if (!((charCode >= 32 && charCode <= 126) || charCode === 13 || charCode === 10 || charCode === 9)) {
            return false;
        }
    }
    return true;
}

/**
 * Convert CBOR-decoded values into JSON-serializable structures.
 */
function jsonSafe(obj) {
    if (obj instanceof Uint8Array || obj instanceof ArrayBuffer) {
        const bytes = obj instanceof Uint8Array ? obj : new Uint8Array(obj);
        try {
            const text = new TextDecoder().decode(bytes);
            if (isPrintableAscii(text)) {
                return text;
            }
        } catch (e) { }
        return btoa(bytes.reduce((data, byte) => data + String.fromCharCode(byte), ''));
    }

    if (obj instanceof Map) {
        const result = {};
        const entries = Array.from(obj.entries());
        for (const [key, value] of entries) {
            result[String(key)] = jsonSafe(value);
        }
        return result;
    }

    if (Array.isArray(obj)) {
        return obj.map(item => jsonSafe(item));
    }

    if (obj !== null && typeof obj === 'object') {
        const result = {};
        for (const [key, value] of Object.entries(obj)) {
            result[key] = jsonSafe(value);
        }
        return result;
    }

    return obj;
}

/**
 * Format attestation document fields for JSON serialization.
 */
function formatAttestationDoc(doc) {
    let publicKeyRaw = doc.public_key;
    if (doc instanceof Map) {
        publicKeyRaw = doc.get('public_key');
    }

    const jsonDoc = jsonSafe(doc);

    // Format PCRs as hex strings
    const pcrsRaw = doc instanceof Map ? doc.get('pcrs') : doc.pcrs;
    if (pcrsRaw) {
        const pcrs = {};
        if (pcrsRaw instanceof Map) {
            const entries = Array.from(pcrsRaw.entries());
            for (const [key, value] of entries) {
                pcrs[String(key)] = (value instanceof Uint8Array) ? bytesToHex(value) : jsonSafe(value);
            }
        } else {
            for (const [key, value] of Object.entries(pcrsRaw)) {
                pcrs[key] = (value instanceof Uint8Array) ? bytesToHex(value) : jsonSafe(value);
            }
        }
        jsonDoc.pcrs = pcrs;
    }

    // Format public key
    if (publicKeyRaw instanceof Uint8Array) {
        const derKey = rawToDer(publicKeyRaw);
        jsonDoc.public_key = bytesToHex(derKey);
    }

    // Format certificate
    const certificateRaw = doc instanceof Map ? doc.get('certificate') : doc.certificate;
    if (certificateRaw instanceof Uint8Array) {
        jsonDoc.certificate = bytesToPem('CERTIFICATE', certificateRaw);
    }

    // Format cabundle
    const cabundleRaw = doc instanceof Map ? doc.get('cabundle') : doc.cabundle;
    if (Array.isArray(cabundleRaw)) {
        jsonDoc.cabundle = cabundleRaw.map((item) =>
            (item instanceof Uint8Array) ? bytesToPem('CERTIFICATE', item) : jsonSafe(item)
        );
    }

    // Format user_data
    const userDataRaw = doc instanceof Map ? doc.get('user_data') : doc.user_data;
    if (userDataRaw instanceof Uint8Array) {
        try {
            const decoded = new TextDecoder().decode(userDataRaw);
            if (isPrintableAscii(decoded)) {
                try {
                    jsonDoc.user_data = JSON.parse(decoded);
                } catch (e) {
                    jsonDoc.user_data = decoded;
                }
            } else {
                jsonDoc.user_data = bytesToHex(userDataRaw);
            }
        } catch (e) {
            jsonDoc.user_data = bytesToHex(userDataRaw);
        }
    }

    return jsonDoc;
}

/**
 * Decode base64-encoded CBOR attestation document.
 */
export async function decodeAttestationDoc(base64Doc) {
    const cbor = await import('cbor-web');

    const binary = atob(base64Doc);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    try {
        const cborData = cbor.decode(bytes);

        if (Array.isArray(cborData) && cborData.length >= 3) {
            const protectedHeaderRaw = cborData[0];
            let protectedHeader = protectedHeaderRaw;
            if (protectedHeaderRaw instanceof Uint8Array) {
                try {
                    protectedHeader = cbor.decode(protectedHeaderRaw);
                } catch (e) { }
            }

            const unprotectedHeader = cborData[1];
            const payload = cborData[2];
            const signature = cborData.length > 3 ? cborData[3] : null;

            const attestationDoc = cbor.decode(payload);
            const formattedDoc = formatAttestationDoc(attestationDoc);

            return {
                protected_header: jsonSafe(protectedHeader),
                unprotected_header: jsonSafe(unprotectedHeader),
                attestation_document: formattedDoc,
                signature: signature instanceof Uint8Array ? bytesToHex(signature) : jsonSafe(signature),
                module_id: formattedDoc.module_id,
                digest: formattedDoc.digest,
                timestamp: formattedDoc.timestamp,
                pcrs: formattedDoc.pcrs,
                public_key: formattedDoc.public_key,
                user_data: typeof formattedDoc.user_data === 'object' ? JSON.stringify(formattedDoc.user_data) : formattedDoc.user_data,
                certificate: formattedDoc.certificate,
                cabundle: formattedDoc.cabundle,
                nonce: formattedDoc.nonce,
            };
        } else {
            const formattedDoc = formatAttestationDoc(cborData);
            return {
                attestation_document: formattedDoc,
                module_id: formattedDoc.module_id,
                digest: formattedDoc.digest,
                timestamp: formattedDoc.timestamp,
                pcrs: formattedDoc.pcrs,
                public_key: formattedDoc.public_key,
                user_data: typeof formattedDoc.user_data === 'object' ? JSON.stringify(formattedDoc.user_data) : formattedDoc.user_data,
                certificate: formattedDoc.certificate,
                cabundle: formattedDoc.cabundle,
                nonce: formattedDoc.nonce,
            };
        }
    } catch (e) {
        console.error('Failed to parse CBOR attestation:', e);
        throw new Error('Failed to parse attestation data');
    }
}
