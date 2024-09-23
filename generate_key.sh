#bash
mkdir ecc_key
cd ecc_key
# create private key for device A/B
openssl ecparam -genkey -name secp256r1 -out deviceA_private_key.pem
openssl ecparam -genkey -name secp256r1 -out deviceB_private_key.pem

# create private key for device A/B
openssl ec -in deviceA_private_key.pem -pubout -out deviceA_public_key.pem
openssl ec -in deviceB_private_key.pem -pubout -out deviceB_public_key.pem

# convert pem to der
openssl ec -in deviceA_private_key.pem -outform der -out deviceA_private_key.der
openssl ec -in deviceA_public_key.pem -pubin -outform der -out deviceA_public_key.der

openssl ec -in deviceB_private_key.pem -outform der -out deviceB_private_key.der
openssl ec -in deviceB_public_key.pem -pubin -outform der -out deviceB_public_key.der

# exgtract key to raw file.
cd ../pythonScript/
python3 extract_private_key_to_raw.py ../ecc_key/deviceA_private_key.der
python3 extract_private_key_to_raw.py ../ecc_key/deviceB_private_key.der
python3 extract_public_key_to_raw.py ../ecc_key/deviceA_public_key.der
python3 extract_public_key_to_raw.py ../ecc_key/deviceB_public_key.der

# convert der to c header file as consnt uint8_t*
python3 convertfile_c_header.py deviceA_key ../ecc_key/deviceA_private_key_raw.bin ../ecc_key/deviceA_public_key_raw.bin
python3 convertfile_c_header.py deviceB_key ../ecc_key/deviceB_private_key_raw.bin ../ecc_key/deviceB_public_key_raw.bin



