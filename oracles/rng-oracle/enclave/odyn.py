"""
Enclave helper class for interacting with enclaver's odyn API.

This module provides a simple interface to the odyn API running on localhost:18000
inside the enclave environment.
"""

import json
import requests
from typing import Dict, Any, Optional, Tuple

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class Odyn:
    """Wrapper for enclaver's odyn API with encryption support."""
    
    DEFAULT_MOCK_ODYN_API = "http://odyn.sparsity.cloud:18000"
    
    def __init__(self, endpoint: Optional[str] = None):
        """
        Initialize the Odyn helper.
        
        Args:
            endpoint: The odyn API endpoint. If None, it automatically chooses
                between localhost:18000 (in Docker) and the mock API.
        """
        if endpoint:
            self.endpoint = endpoint
        else:
            is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
            self.endpoint = "http://localhost:18000" if is_enclave else self.DEFAULT_MOCK_ODYN_API
    
    def eth_address(self) -> str:
        """
        Get the Ethereum address from the enclave.
        
        Returns:
            The Ethereum address as a string.
        """
        res = requests.get(f"{self.endpoint}/v1/eth/address", timeout=10)
        res.raise_for_status()
        return res.json()["address"]
    
    def get_attestation(self) -> bytes:
        """
        Get the attestation document as raw CBOR binary.
        
        This method returns the raw CBOR attestation document without base64 encoding,
        matching the format returned by the enclaver runtime in production.
        
        Returns:
            Raw CBOR attestation document bytes.
        """
        # Get the encryption public key for attestation API
        encryption_pub_data = self.get_encryption_public_key_data()
        encryption_pub_key_pem = encryption_pub_data["public_key_pem"]
        
        payload = {
            "nonce": "",
            "public_key": encryption_pub_key_pem,
        }
        
        res = requests.post(
            f"{self.endpoint}/v1/attestation",
            json=payload,
            timeout=10
        )
        res.raise_for_status()
        
        # Return raw CBOR binary
        return res.content
    
    def get_encryption_public_key_data(self) -> Dict[str, str]:
        """
        Retrieve the enclave's encryption public key data.
        
        Returns:
            Dict containing 'public_key_der' (hex) and 'public_key_pem'.
        """
        res = requests.get(f"{self.endpoint}/v1/encryption/public_key", timeout=10)
        res.raise_for_status()
        return res.json()
    
    def get_encryption_public_key_der(self) -> bytes:
        """
        Get the encryption public key in DER format.
        
        Returns:
            DER-encoded public key bytes.
        """
        pub_data = self.get_encryption_public_key_data()
        pub_key_hex = pub_data["public_key_der"]
        if pub_key_hex.startswith("0x"):
            pub_key_hex = pub_key_hex[2:]
        return bytes.fromhex(pub_key_hex)
    
    def get_random_bytes(self, count: int = 32) -> bytes:
        """
        Get random bytes from the enclave.
        
        Args:
            count: Number of random bytes to generate.
            
        Returns:
            Random bytes.
        """
        res = requests.get(f"{self.endpoint}/v1/random", timeout=10)
        res.raise_for_status()
        random_hex = res.json()["random_bytes"]
        # Remove 0x prefix if present
        if random_hex.startswith("0x"):
            random_hex = random_hex[2:]
        return bytes.fromhex(random_hex)[:count]
    
    def sign_message(self, data: Dict[str, Any]) -> str:
        """Sign a dict payload by canonical JSON then /v1/eth/sign (EIP-191 prefix inside enclaver)."""
        message = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return self.sign_data(message)

    def sign_data(self, data: str) -> str:
        """
        Sign plain text data using enclaver's /v1/eth/sign (EIP-191 inside enclaver).
        Returns hex signature without 0x prefix for verifier compatibility.
        In dev mode, returns empty string if signing fails.
        """
        try:
            res = requests.post(
                f"{self.endpoint}/v1/eth/sign",
                json={
                    "message": data,
                    "include_attestation": False
                },
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            res.raise_for_status()
            sig = res.json()["signature"]
            return sig[2:] if sig.startswith("0x") else sig
        except Exception as e:
            # In dev mode, signing may fail - return empty signature
            import logging
            logging.warning(f"Signing failed (dev mode): {e}")
            return ""
    
        
    def decrypt_data(self, nonce_hex: str, client_public_key_hex: str, 
                     encrypted_data_hex: str) -> str:
        """
        Decrypt data encrypted by a client using Odyn API.
        
        Args:
            nonce_hex: Nonce in hex
            client_public_key_hex: Client's ephemeral public key (DER format, hex)
            encrypted_data_hex: AES-GCM encrypted data (hex)
            
        Returns:
            Decrypted plaintext string
        """
        # Use only first 12 bytes of nonce for standard AES-GCM compatibility
        nonce_bytes = bytes.fromhex(nonce_hex)
        if len(nonce_bytes) > 12:
            nonce_hex = nonce_bytes[:12].hex()
            
        payload = {
            "nonce": nonce_hex if nonce_hex.startswith("0x") else f"0x{nonce_hex}",
            "client_public_key": client_public_key_hex if client_public_key_hex.startswith("0x") else f"0x{client_public_key_hex}",
            "encrypted_data": encrypted_data_hex if encrypted_data_hex.startswith("0x") else f"0x{encrypted_data_hex}"
        }
        
        res = requests.post(
            f"{self.endpoint}/v1/encryption/decrypt",
            json=payload,
            timeout=10
        )
        res.raise_for_status()
        return res.json()["plaintext"]
    
    def encrypt_data(self, data: str, client_public_key_der: bytes) -> Tuple[str, str, str]:
        """
        Encrypt data to send back to the client using Odyn API.
        
        Args:
            data: Plaintext string to encrypt
            client_public_key_der: Client's public key in DER format
            
        Returns:
            Tuple of (encrypted data hex, our public key hex, response nonce hex)
        """
        client_public_key_hex = client_public_key_der.hex()
        payload = {
            "plaintext": data,
            "client_public_key": f"0x{client_public_key_hex}" if not client_public_key_hex.startswith("0x") else client_public_key_hex
        }
        
        res = requests.post(
            f"{self.endpoint}/v1/encryption/encrypt",
            json=payload,
            timeout=10
        )
        res.raise_for_status()
        
        res_json = res.json()
        encrypted_data = res_json["encrypted_data"]
        enclave_public_key = res_json["enclave_public_key"]
        nonce = res_json["nonce"]
        
        # Remove 0x prefixes if present for result consistency
        if encrypted_data.startswith("0x"): encrypted_data = encrypted_data[2:]
        if enclave_public_key.startswith("0x"): enclave_public_key = enclave_public_key[2:]
        if nonce.startswith("0x"): nonce = nonce[2:]
        
        return encrypted_data, enclave_public_key, nonce


if __name__ == '__main__':
    # Test the Odyn helper
    import binascii
    
    e = Odyn()
    
    print("--- Basic Info ---")
    addr = e.eth_address()
    print(f"Ethereum address: {addr}")
    
    rand = e.get_random_bytes(16)
    print(f"Random bytes (16): {rand.hex()}")
    
    print("\n--- Encryption Public Key ---")
    pub_data = e.get_encryption_public_key_data()
    print(f"Public Key PEM: {pub_data['public_key_pem'][:50]}...")
    
    pub_der = e.get_encryption_public_key_der()
    print(f"Public Key DER (first 20 bytes): {pub_der[:20].hex()}...")

    print("\n--- Attestation ---")
    att = e.get_attestation()
    print(f"Attestation length: {len(att)} bytes")
    
    print("\n--- Signing ---")
    test_payload = {"test": "data", "addr": addr}
    sig = e.sign_message(test_payload)
    print(f"Payload signature: {sig}")

    print("\n--- Encryption/Decryption ---")
    # 1. Simulate a client generating a P-384 keypair (using standard cryptography library)
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    client_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    client_public_key_der = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 2. Test Decryption: Client encrypts for Odyn
    print("Testing Decryption (Client -> Odyn)...")
    server_public_key = serialization.load_der_public_key(pub_der, backend=default_backend())
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"encryption data"
    ).derive(shared_secret)
    
    plaintext = "Secret message from client"
    nonce = e.get_random_bytes(12) 
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), None)
    
    decrypted = e.decrypt_data(nonce.hex(), client_public_key_der.hex(), ciphertext.hex())
    print(f"Decrypted by Odyn: {decrypted}")
    assert plaintext == decrypted

    # 3. Test Encryption: Odyn encrypts for Client
    print("\nTesting Encryption (Odyn -> Client)...")
    response_text = "Hello from the Odyn!"
    enc_data, enc_pub_key, enc_nonce = e.encrypt_data(response_text, client_public_key_der)
    
    # Client decrypts using the derived key
    # IMPORTANT: We use only the first 12 bytes of the nonce for standard AES-GCM
    client_decrypted = AESGCM(aes_key).decrypt(bytes.fromhex(enc_nonce)[:12], bytes.fromhex(enc_data), None)
    print(f"Decrypted by Client: {client_decrypted.decode()}")
    assert response_text == client_decrypted.decode()
    
    print("\nAll tests passed successfully!")
