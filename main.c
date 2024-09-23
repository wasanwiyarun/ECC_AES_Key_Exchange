#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

void handle_error()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void publicKey_encrypt_privateKey_decrypt_test()
{
 
}

void signature_test()
{
    
}

int main()
{
    printf("Program Start\r\n");

    return 0;
}
