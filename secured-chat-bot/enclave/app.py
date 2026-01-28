#!/usr/bin/env python3
"""
New AI Chatbot - A TEE-based AI chat service with API key caching.

This service runs inside an AWS Nitro Enclave using the enclaver tool.
It provides secure AI chat functionality with signed responses.
Features:
- API key caching (set via encrypted /set-api-key endpoint)
- Full E2E encryption for all communications
- Attestation via /.well-known/attestation (provided by enclave runtime)
"""

import json
import os
import time
import logging
from typing import Dict, Any, Optional

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from odyn import Odyn
from ai_models.open_ai import OpenAI
from ai_models.platform import Platform

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Allow all origins

# Initialize odyn helper
odyn = Odyn()

# Platform mapping
PLATFORM_MAPPING: Dict[str, type] = {
    "openai": OpenAI,
}

# Cached API key (set via encrypted /set-api-key endpoint)
# SECURITY: Never expose this value in any response
_cached_api_key: Optional[str] = None
_cached_platform: Optional[str] = None


@app.route('/')
def index():
    """Health check endpoint with service information and API key status."""
    try:
        address = odyn.eth_address()
        frontend_available = os.path.exists(FRONTEND_DIR) and os.path.isfile(os.path.join(FRONTEND_DIR, 'index.html'))
        return jsonify({
            "status": "ok",
            "service": "Secured Chatbot",
            "version": "1.0.0",
            "enclave_address": address,
            "api_key_available": _cached_api_key is not None,
            "cached_platform": _cached_platform,
            "frontend_available": frontend_available,
            "supported_platforms": list(PLATFORM_MAPPING.keys()),
            "endpoints": {
                "/": "Health check and service info (includes api_key_available status)",
                "/frontend": "Static frontend files",
                "/set-api-key": "POST - Set API key (encrypted)",
                "/talk": "POST - Send chat message (encrypted)"
            },
            "note": "Attestation available at /.well-known/attestation"
        })
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


# Frontend static files directory
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "frontend"))


@app.route('/frontend/')
@app.route('/frontend/<path:path>')
def serve_frontend(path=''):
    """
    Serve static files from the frontend build directory.
    Supports SPA routing with fallback to index.html.
    """
    if not os.path.exists(FRONTEND_DIR):
        return jsonify({"error": "Frontend not available"}), 404
    
    # If path is empty, serve index.html
    if not path or path == '':
        return send_from_directory(FRONTEND_DIR, 'index.html')
    
    # Try to serve the requested file
    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(file_path):
        return send_from_directory(FRONTEND_DIR, path)
    
    # For SPA: fallback to index.html for client-side routing
    return send_from_directory(FRONTEND_DIR, 'index.html')


# Only register /.well-known/attestation in local dev mode (not in Docker)
# In Docker, the enclaver runtime provides this endpoint
if os.getenv("IN_DOCKER", "False").lower() != "true":
    @app.route('/.well-known/attestation', methods=['POST'])
    def attestation():
        """
        Get attestation document from the enclave (local dev only).
        
        Returns raw CBOR binary matching the production enclaver runtime format.
        The CBOR contains a COSE Sign1 structure with the attestation document.
        """
        try:
            # Get raw CBOR attestation (same format as production)
            attestation_cbor = odyn.get_attestation()
            
            # Return raw CBOR with proper content type
            from flask import Response
            return Response(
                attestation_cbor,
                mimetype='application/cbor'
            )
        except Exception as e:
            logger.error(f"Attestation error: {e}")
            return jsonify({"error": str(e)}), 500


@app.route('/set-api-key', methods=['POST'])
def set_api_key():
    """
    Set the cached API key (encrypted endpoint).
    
    Expected JSON body (encrypted format):
    {
        "nonce": "hex-encoded-32-bytes",
        "public_key": "hex-encoded-DER-public-key",
        "data": "hex-encoded-encrypted-json"
    }
    
    The encrypted data should contain:
    {
        "api_key": "your-api-key",
        "platform": "openai"  // optional, defaults to "openai"
    }
    
    Returns encrypted response confirming the key was set.
    """
    global _cached_api_key, _cached_platform
    
    try:
        request_data = request.get_json()
        
        if not request_data:
            return jsonify({"error": "Request body is required"}), 400
        
        # Must be encrypted request
        if "nonce" not in request_data or "public_key" not in request_data or "data" not in request_data:
            return jsonify({"error": "Encrypted request required (nonce, public_key, data)"}), 400
        
        nonce_hex = request_data.get("nonce", "")
        client_public_key_hex = request_data.get("public_key", "")
        encrypted_data_hex = request_data.get("data", "")
        
        if not nonce_hex or not client_public_key_hex or not encrypted_data_hex:
            return jsonify({"error": "nonce, public_key, and data are required"}), 400
        
        # Decrypt the request
        logger.info("Decrypting set-api-key request...")
        try:
            decrypted_str = odyn.decrypt_data(
                nonce_hex, client_public_key_hex, encrypted_data_hex
            )
            data = json.loads(decrypted_str)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400
        
        # Extract and validate API key
        api_key = data.get("api_key", "")
        platform = data.get("platform", "openai")
        
        if not api_key:
            return jsonify({"error": "api_key is required"}), 400
        
        if platform not in PLATFORM_MAPPING:
            return jsonify({
                "error": f"Invalid platform: {platform}. Supported: {list(PLATFORM_MAPPING.keys())}"
            }), 400
        
        # Cache the API key (NEVER expose in response)
        _cached_api_key = api_key
        _cached_platform = platform
        logger.info(f"API key cached for platform: {platform}")
        
        # Build encrypted response
        client_public_key_der = bytes.fromhex(client_public_key_hex)
        response_data = {
            "status": "success",
            "message": "API key cached successfully",
            "platform": platform,
            "timestamp": int(time.time())
        }
        
        response_json = json.dumps(response_data, sort_keys=True, separators=(',', ':'))
        encrypted_response, server_public_key_hex, response_nonce_hex = odyn.encrypt_data(
            response_json, client_public_key_der
        )
        
        encrypted_envelope = {
            "nonce": response_nonce_hex,
            "public_key": server_public_key_hex,
            "encrypted_data": encrypted_response
        }
        
        signature = odyn.sign_message(encrypted_envelope)
        
        return jsonify({
            "sig": signature,
            "data": encrypted_envelope
        })
        
    except Exception as e:
        logger.error(f"Set API key error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/talk', methods=['POST'])
def talk():
    """
    Main chat endpoint. Receives an encrypted message and returns an encrypted, signed AI response.
    Uses cached API key if available.
    
    Expected JSON body (encrypted format):
    {
        "nonce": "hex-encoded-32-bytes",
        "public_key": "hex-encoded-DER-public-key",
        "data": "hex-encoded-encrypted-json"
    }
    
    The encrypted data should contain:
    {
        "message": "Hello, AI!",
        "ai_model": "gpt-4"  // optional, defaults to "gpt-4"
    }
    
    Returns encrypted, signed response.
    """
    try:
        request_data = request.get_json()
        
        if not request_data:
            return jsonify({"error": "Request body is required"}), 400
        
        # Must be encrypted request
        if "nonce" not in request_data or "public_key" not in request_data or "data" not in request_data:
            return jsonify({"error": "Encrypted request required (nonce, public_key, data)"}), 400
        
        nonce_hex = request_data.get("nonce", "")
        client_public_key_hex = request_data.get("public_key", "")
        encrypted_data_hex = request_data.get("data", "")
        
        if not nonce_hex or not client_public_key_hex or not encrypted_data_hex:
            return jsonify({"error": "nonce, public_key, and data are required"}), 400
        
        # Decrypt the request
        logger.info("Decrypting incoming request...")
        try:
            decrypted_str = odyn.decrypt_data(
                nonce_hex, client_public_key_hex, encrypted_data_hex
            )
            data = json.loads(decrypted_str)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400
        
        client_public_key_der = bytes.fromhex(client_public_key_hex)
        
        # Extract fields from decrypted data
        message = data.get("message", "")
        ai_model = data.get("ai_model", "gpt-4")
        
        # Check if API key is cached
        if not _cached_api_key:
            return jsonify({"error": "API key not set. Call /set-api-key first."}), 400
        
        if not message:
            return jsonify({"error": "message is required"}), 400
        
        # Use cached platform
        platform = _cached_platform or "openai"
        platform_class = PLATFORM_MAPPING.get(platform)
        
        if platform_class is None:
            return jsonify({
                "error": f"Invalid platform: {platform}. Supported: {list(PLATFORM_MAPPING.keys())}"
            }), 400
        
        # Create platform client and validate model
        client: Platform = platform_class(_cached_api_key)
        if not client.check_support_model(ai_model):
            return jsonify({
                "error": f"Invalid model: {ai_model}. Supported for {platform}: {client.support_models}"
            }), 400
        
        # Call AI model
        logger.info(f"Calling {platform}/{ai_model} with message: {message[:50]}...")
        resp_content, resp_timestamp = client.call(ai_model, message)
        
        # Build response data
        response_data = {
            "platform": platform,
            "ai_model": ai_model,
            "timestamp": resp_timestamp,
            "message": message,
            "response": resp_content
        }
        
        # Encrypt the response
        logger.info("Encrypting response...")
        response_json = json.dumps(response_data, sort_keys=True, separators=(',', ':'))
        encrypted_response, server_public_key_hex, response_nonce_hex = odyn.encrypt_data(
            response_json, client_public_key_der
        )
        
        # Build encrypted response envelope
        encrypted_envelope = {
            "nonce": response_nonce_hex,
            "public_key": server_public_key_hex,
            "encrypted_data": encrypted_response
        }
        
        # Sign the encrypted envelope
        signature = odyn.sign_message(encrypted_envelope)
        
        return jsonify({
            "sig": signature,
            "data": encrypted_envelope
        })
        
    except Exception as e:
        logger.error(f"Talk error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    logger.info("Starting New AI Chatbot service...")
    logger.info(f"Odyn endpoint: {odyn.endpoint}") # Changed ODYN_API to odyn.endpoint
    logger.info("Endpoints:")
    logger.info("  GET  /             - Health check (includes api_key_available)")
    logger.info("  POST /set-api-key  - Set API key (encrypted)")
    logger.info("  POST /talk         - Send chat message (encrypted)")
    logger.info("Note: Attestation at /.well-known/attestation (enclave runtime)")
    
    app.run(host='0.0.0.0', port=8000)
