#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import requests
import base64
import json
import sys
from pathlib import Path

def convert_attestation_to_report(url: str, output_file: str) -> None:
    """
    Converts attestation JSON from URL to binary .report format
    """
    # Fetch the attestation JSON from the URL
    response = requests.get(url)
    # Raise exception if request failed
    response.raise_for_status()
    
    # Parse JSON response
    attestation_json = response.json()
    
    # Extract the attestation_doc field
    attestation_doc_b64 = attestation_json.get('attestation_doc')
    # Check if attestation_doc exists
    if not attestation_doc_b64:
        raise ValueError("No 'attestation_doc' field found in JSON response")
    
    # Decode base64 to get raw CBOR bytes
    attestation_bytes = base64.b64decode(attestation_doc_b64)
    
    # Write binary data to .report file
    output_path = Path(output_file)
    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Write bytes to file
    with open(output_path, 'wb') as f:
        f.write(attestation_bytes)
    
    # Print success message with file size
    print(f"Successfully converted attestation to {output_file}")
    print(f"File size: {len(attestation_bytes)} bytes")

def main():
    """
    Main entry point - accepts URL and output file as arguments
    """
    # Check if correct number of arguments provided
    if len(sys.argv) < 2:
        print("Usage: python convert_attestation.py <url> [output_file]")
        print("Example: python convert_attestation.py http://example.com/attestation attestation.report")
        sys.exit(1)
    
    # Get URL from first argument
    url = sys.argv[1]
    # Get output file from second argument or use default
    output_file = sys.argv[2] if len(sys.argv) > 2 else "attestation.report"
    
    try:
        # Convert and save attestation
        convert_attestation_to_report(url, output_file)
    except requests.exceptions.RequestException as e:
        # Handle network/HTTP errors
        print(f"Error fetching attestation: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        # Handle parsing errors
        print(f"Error parsing attestation: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Handle any other errors
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Run main function when script is executed
    main()
