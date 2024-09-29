#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include "deviceA_key.h"
#include "deviceB_key.h"
#include <openssl/rand.h>
#include <openssl/sha.h>

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void print_hex(char *title, uint8_t data[], size_t len)
{
    if (title == NULL || data == NULL || len == 0)
    {
        printf("Error, parameter is incorrect.\r\n");
        return;
    }
    else
    {
        printf("%s:\r\n", title);
        for (size_t i = 0; i < len; i++)
        {
            if (i % 16 == 0 && i != 0)
            {
                printf("\r\n");
            }
            printf("0x%02X,", data[i]);
        }
        printf("\r\n");
    }
}

int create_shared_key(const uint8_t *priv_key_der, size_t priv_key_len,
                      const uint8_t *pub_key_der, size_t pub_key_len,
                      uint8_t *shared_secret, size_t *shared_secret_len)
{
    printf("Start create shared secret key\r\n");
    int ret = 0;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len = 0;

    // Load private key from DER
    const unsigned char *ppriv = priv_key_der;
    private_key = d2i_PrivateKey(EVP_PKEY_EC, NULL, &ppriv, priv_key_len);
    if (!private_key)
    {
        fprintf(stderr, "Error loading private key\r\n");
        ret = -1;
        goto cleanup;
    }

    // Load public key from DER
    const unsigned char *ppub = pub_key_der;
    public_key = d2i_PUBKEY(NULL, &ppub, pub_key_len);
    if (!public_key)
    {
        fprintf(stderr, "Error loading public key\r\n");
        ret = -1;
        goto cleanup;
    }

    // Create context for shared secret derivation
    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx)
    {
        fprintf(stderr, "Error creating context\r\n");
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        fprintf(stderr, "Error initializing derivation\r\n");
        goto cleanup;
    }

    // Provide the peer's public key for shared secret derivation
    if (EVP_PKEY_derive_set_peer(ctx, public_key) <= 0)
    {
        fprintf(stderr, "Error setting peer key\r\n");
        ret = -1;
        goto cleanup;
    }

    // Determine buffer length for shared secret
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0)
    {
        fprintf(stderr, "Insufficient buffer size\r\n");
        ret = -1;
        goto cleanup;
    }

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0)
    {
        fprintf(stderr, "Error deriving shared secret\r\n");
        ret = -1;
        goto cleanup;
    }

    // Output the shared secret
    *shared_secret_len = secret_len;

cleanup:
    if (private_key)
    {
        EVP_PKEY_free(private_key);
    }
    if (public_key)
    {
        EVP_PKEY_free(public_key);
    }
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    return ret;
}

int generate_AES_KEY_256(uint8_t *shared_secret_key, const size_t shared_secret_key_len, uint8_t *aes_key_output, size_t aes_key_output_len)
{
    int ret = 0;
    const size_t header_data_size = 4; // Assuming this is a fixed size
    const size_t tail_data_size = 128; // Salt size
    uint8_t header_data[4] = {0x00, 0x01, 0x02, 0x03}; // Example header data
    EVP_MD_CTX *mdctx = NULL;
    
    if (shared_secret_key == NULL || aes_key_output == NULL || aes_key_output_len < 32)
    {
        printf("Error, parameter is NULL or aes key buffer size less than 32 bytes (256 bits).\r\n");
        ret = -1;
    }
    else
    {

        uint8_t input_buffer[header_data_size + shared_secret_key_len + tail_data_size];
        memset(input_buffer, 0x00, sizeof(input_buffer));
        int err_code = RAND_bytes(&input_buffer[header_data_size + shared_secret_key_len], tail_data_size);
        if (err_code != 1)
        {
            printf("Add salt for input buffer fail\r\n");
            ret = -2;
        }
        else
        {
            memcpy(&input_buffer[header_data_size], shared_secret_key, shared_secret_key_len);
            memcpy(input_buffer, header_data, sizeof(header_data));
            print_hex("input buffer with salt", input_buffer, sizeof(input_buffer));

            mdctx = EVP_MD_CTX_new();

            if (mdctx == NULL)
            {
                printf("EVP_MD_CTX_new fail\r\n");
                ret = -2;
            }
            else
            {
                err_code = EVP_DigestInit(mdctx, EVP_sha256());
                if (err_code != 1)
                {
                    printf("EVP_DigestInit fail\r\n");
                    ret = -2;
                }
                else
                {
                    err_code = EVP_DigestUpdate(mdctx, input_buffer, sizeof(input_buffer));
                    if (err_code != 1)
                    {
                        printf("EVP_DigestUpdate fail\r\n");
                        ret = -2;
                    }
                    else
                    {
                        unsigned int hash_len = 0;
                        err_code = EVP_DigestFinal(mdctx, aes_key_output, &hash_len);
                        if (err_code != 1)
                        {
                            printf("EVP_DigestFinal fail\r\n");
                            ret = -2;
                        }
                        else
                        {
                            print_hex("aes key", aes_key_output, aes_key_output_len);
                            printf("hash size:%d\r\n", hash_len);
                        }
                    }
                }
            }
        }
    }

    if(mdctx)
    {
        EVP_MD_CTX_free(mdctx);
    }

    return ret;
}

void shared_key_and_create_aes_key_test()
{
    int ret = 0;
    uint8_t a_device_shared_secret[32] = {0};
    size_t a_device_shared_secret_len = sizeof(a_device_shared_secret);
    uint8_t b_device_shared_secret[32] = {0};
    size_t b_device_shared_secret_len = sizeof(b_device_shared_secret);

    ret = create_shared_key(deviceA_private_key, deviceA_private_key_size, deviceB_public_key, deviceB_public_key_size, a_device_shared_secret, &a_device_shared_secret_len);
    if (ret != 0)
    {
        handle_errors();
    }

    printf("At Device A, shared_secret_len:%ld\r\n", a_device_shared_secret_len);
    print_hex("shared_secret key", a_device_shared_secret, a_device_shared_secret_len);

    ret = create_shared_key(deviceA_private_key, deviceA_private_key_size, deviceB_public_key, deviceB_public_key_size, b_device_shared_secret, &b_device_shared_secret_len);
    if (ret != 0)
    {
        handle_errors();
    }

    printf("At Device B, shared_secret_len:%ld\r\n", a_device_shared_secret_len);
    print_hex("shared_secret key", a_device_shared_secret, a_device_shared_secret_len);

    if (0 == memcmp(a_device_shared_secret, b_device_shared_secret, a_device_shared_secret_len))
    {
        printf("shared_secret key match\r\n");
    }
    else
    {
        printf("shared_secret key do not match\r\n");
    }

    uint8_t aes_encrypt_decrypt_key[32] = {0};
    generate_AES_KEY_256(a_device_shared_secret, a_device_shared_secret_len, aes_encrypt_decrypt_key, sizeof(aes_encrypt_decrypt_key));
}

void signature_test()
{
    
}

int main()
{
    printf("Program Start\r\n");

    shared_key_and_create_aes_key_test();

    return 0;
}
