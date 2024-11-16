#include "kms_client.h"
#include <stdio.h>

int main() {
    // Initialize client with your AWS credentials
    KMSClient *client = kms_client_init(
        "us-east-2",
        getenv("AWS_ACCESS_KEY_ID"),
        getenv("AWS_SECRET_ACCESS_KEY")
    );

    if (!client) {
        fprintf(stderr, "Failed to initialize KMS client\n");
        return 1;
    }

    // Create a new KMS key
    char *key_id = kms_create_key(client, "Example encryption key");
    if (!key_id) {
        fprintf(stderr, "Failed to create KMS key\n");
        kms_client_cleanup(client);
        return 1;
    }
    printf("Created KMS key: %s\n", key_id);

    // Example data to encrypt
    const char *plaintext = "Hello, KMS!";
    
    // Encrypt data
    char *ciphertext = kms_encrypt(client, key_id, 
                                 (const unsigned char*)plaintext, 
                                 strlen(plaintext));
    if (!ciphertext) {
        fprintf(stderr, "Encryption failed\n");
        free(key_id);
        kms_client_cleanup(client);
        return 1;
    }
    printf("Encrypted data: %s\n", ciphertext);

    // Decrypt data
    size_t decrypted_len;
    unsigned char *decrypted = kms_decrypt(client, ciphertext, &decrypted_len);
    if (!decrypted) {
        fprintf(stderr, "Decryption failed\n");
        free(ciphertext);
        free(key_id);
        kms_client_cleanup(client);
        return 1;
    }
    printf("Decrypted data: %.*s\n", (int)decrypted_len, decrypted);

    // Cleanup
    free(decrypted);
    free(ciphertext);
    free(key_id);
    kms_client_cleanup(client);

    return 0;
}
