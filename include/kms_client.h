#ifndef KMS_CLIENT_H
#define KMS_CLIENT_H

#include <curl/curl.h>
#include <json-c/json.h>
#include <string.h>
#include <stdlib.h>

// Response structure
typedef struct {
    char *data;
    size_t size;
} KMSResponse;

// KMS client configuration
typedef struct {
    char *region;
    char *access_key;
    char *secret_key;
    char *session_token;  // Optional
    CURL *curl;
} KMSClient;

// Initialize and cleanup
KMSClient* kms_client_init(const char *region, const char *access_key, const char *secret_key);
void kms_client_cleanup(KMSClient *client);

// KMS operations
char* kms_create_key(KMSClient *client, const char *description);
char* kms_encrypt(KMSClient *client, const char *key_id, const unsigned char *data, size_t data_len);
unsigned char* kms_decrypt(KMSClient *client, const char *ciphertext_blob, size_t *plaintext_len);

#endif
