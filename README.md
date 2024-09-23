
# ECC-AES Key Exchange between Device A and Device B

This repository demonstrates how to generate ECC (Elliptic Curve Cryptography) key pairs for two devices (Device A and Device B), perform key exchange using ECDH (Elliptic Curve Diffie-Hellman), and convert the shared secret to an AES key to encrypt and decrypt data.

## Steps to Generate ECC Keys for Device A and Device B

### 1. Generate ECC Private and Public Keys for Device A

1.1 **Generate a Private Key for Device A/B**
```bash
$ openssl ecparam -genkey -name secp256r1 -out deviceA_private.pem
$ openssl ecparam -genkey -name secp256r1 -out deviceB_private.pem
```

1.2 **Generate the Public Key for Device A/B**
```bash
$ openssl ec -in deviceA_private.pem -pubout -out deviceA_public.pem
$ openssl ec -in deviceB_private.pem -pubout -out deviceB_public.pem
```

### 2. Convert PEM to DER
The next step is to convert both the private and public keys from PEM format to DER format using OpenSSL.

3.1 Private Key Conversion (PEM to DER)
```bash
$ openssl ec -in deviceA_private.pem -outform der -out deviceA_private.der
$ openssl ec -in deviceB_private.pem -outform der -out deviceB_private.der
```

3.2 Public Key Conversion (PEM to DER)
```bash
$ openssl ec -in deviceA_public.pem -pubin -outform der -out deviceA_public.der
$ openssl ec -in deviceB_public.pem -pubin -outform der -out deviceB_public.der
```

### 4. Extract Raw Binary from DER Files
Once the keys are in DER format, you can extract the raw binary key data.



### Key Files Generated

- **Device A:**
  - `deviceA_private.pem` (Private key for Device A)
  - `deviceA_public.pem` (Public key for Device A)

- **Device B:**
  - `deviceB_private.pem` (Private key for Device B)
  - `deviceB_public.pem` (Public key for Device B)

### 3. Key Exchange and AES Encryption

Once Device A and Device B have generated their key pairs, they can exchange their **public keys**. Both devices can compute a shared secret using their own private key and the other device's public key. This shared secret can then be converted to a 256-bit AES key for data encryption and decryption.

### Next Steps

You can implement the key exchange using ECDH and use the resulting shared key to encrypt and decrypt data with AES. Examples in various languages (like Python or C) can be used for this step, depending on your project needs.
