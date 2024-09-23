import sys
from cryptography.hazmat.primitives import serialization

def extract_public_key_to_raw(file_name):
    # Load the public key from DER format
    with open(file_name, "rb") as f:
        public_key = serialization.load_der_public_key(f.read())

    # Extract the public key numbers (X and Y coordinates)
    public_numbers = public_key.public_numbers()
    x = public_numbers.x.to_bytes(32, byteorder='big')
    y = public_numbers.y.to_bytes(32, byteorder='big')

    # Define the output file name based on the input
    output_file_name = file_name.replace('.der', '_raw.bin')

    # Save the raw public key (X and Y) to a binary file
    with open(output_file_name, "wb") as f:
        f.write(x + y)

    print(f"Raw public key (X and Y) saved to: {output_file_name}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python extract_public_key_to_raw.py <public_key_file.der>")
        sys.exit(1)

    file_name = sys.argv[1]

    extract_public_key_to_raw(file_name)
