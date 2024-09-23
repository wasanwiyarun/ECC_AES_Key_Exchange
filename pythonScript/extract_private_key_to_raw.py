import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def extract_private_key_to_raw(file_name):
    # Load the private key from DER format
    with open(file_name, "rb") as f:
        private_key = serialization.load_der_private_key(f.read(), password=None)

    # Extract the private key scalar (raw value)
    private_value = private_key.private_numbers().private_value
    private_key_raw = private_value.to_bytes(32, byteorder='big')

    # Define the output file name based on the input
    output_file_name = file_name.replace('.der', '_raw.bin')

    # Save the raw private key to a binary file
    with open(output_file_name, "wb") as f:
        f.write(private_key_raw)

    print(f"Raw private key saved to: {output_file_name}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python extract_private_key_to_raw.py <private_key_file.der>")
        sys.exit(1)

    file_name = sys.argv[1]

    extract_private_key_to_raw(file_name)
