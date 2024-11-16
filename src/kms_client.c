#include <openssl/evp.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include "kms_client.h"

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    KMSResponse *resp = (KMSResponse *)userp;

    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if(!ptr) {
        return 0;
    }

    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;

    return realsize;
}

KMSClient* kms_client_init(const char *region, const char *access_key, const char *secret_key) {
    KMSClient *client = malloc(sizeof(KMSClient));
    if (!client) return NULL;

    client->region = strdup(region);
    client->access_key = strdup(access_key);
    client->secret_key = strdup(secret_key);
    client->session_token = NULL;
    
    client->curl = curl_easy_init();
    if (!client->curl) {
        free(client);
        return NULL;
    }

    // Configure curl for AWS SigV4
    curl_easy_setopt(client->curl, CURLOPT_AWS_SIGV4, "aws");
    curl_easy_setopt(client->curl, CURLOPT_USERNAME, client->access_key);
    curl_easy_setopt(client->curl, CURLOPT_PASSWORD, client->secret_key);
    
    return client;
}

void kms_client_cleanup(KMSClient *client) {
    if (client) {
        free(client->region);
        free(client->access_key);
        free(client->secret_key);
        free(client->session_token);
        curl_easy_cleanup(client->curl);
        free(client);
    }
}

char* kms_create_key(KMSClient *client, const char *description) {
    struct curl_slist *headers = NULL;
    KMSResponse response = {0};
    char *key_id = NULL;

    // Prepare JSON request
    json_object *request = json_object_new_object();
    json_object_object_add(request, "Description", json_object_new_string(description));
    const char *request_str = json_object_to_json_string(request);

    // Set up headers
    headers = curl_slist_append(headers, "Content-Type: application/x-amz-json-1.1");
    headers = curl_slist_append(headers, "X-Amz-Target: TrentService.CreateKey");

    // Set up URL
    char url[256];
    snprintf(url, sizeof(url), "https://kms.%s.amazonaws.com/", client->region);

    // Configure CURL request
    curl_easy_setopt(client->curl, CURLOPT_URL, url);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, request_str);
    curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(client->curl);
    curl_slist_free_all(headers);
    json_object_put(request);

    if (res != CURLE_OK) {
        free(response.data);
        return NULL;
    }

    // Parse response
    json_object *resp_obj = json_tokener_parse(response.data);
    json_object *key_metadata, *key_id_obj;
    
    if (json_object_object_get_ex(resp_obj, "KeyMetadata", &key_metadata) &&
        json_object_object_get_ex(key_metadata, "KeyId", &key_id_obj)) {
        key_id = strdup(json_object_get_string(key_id_obj));
    }

    json_object_put(resp_obj);
    free(response.data);
    return key_id;
}

char* kms_encrypt(KMSClient *client, const char *key_id, const unsigned char *data, size_t data_len) {
    struct curl_slist *headers = NULL;
    KMSResponse response = {0};
    char *ciphertext = NULL;

    // Base64 encode the input data
    size_t b64_len = ((4 * data_len / 3) + 3) & ~3;
    char *b64_data = malloc(b64_len + 1);
    if (!b64_data) return NULL;
    
    EVP_EncodeBlock((unsigned char*)b64_data, data, data_len);

    // Prepare JSON request
    json_object *request = json_object_new_object();
    json_object_object_add(request, "KeyId", json_object_new_string(key_id));
    json_object_object_add(request, "Plaintext", json_object_new_string(b64_data));
    const char *request_str = json_object_to_json_string(request);
    
    free(b64_data);

    // Set up headers
    headers = curl_slist_append(headers, "Content-Type: application/x-amz-json-1.1");
    headers = curl_slist_append(headers, "X-Amz-Target: TrentService.Encrypt");

    // Set up URL
    char url[256];
    snprintf(url, sizeof(url), "https://kms.%s.amazonaws.com/", client->region);

    // Configure CURL request
    curl_easy_setopt(client->curl, CURLOPT_URL, url);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, request_str);
    curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(client->curl);
    curl_slist_free_all(headers);
    json_object_put(request);

    if (res != CURLE_OK) {
        free(response.data);
        return NULL;
    }

    // Parse response
    json_object *resp_obj = json_tokener_parse(response.data);
    json_object *ciphertext_blob;
    
    if (json_object_object_get_ex(resp_obj, "CiphertextBlob", &ciphertext_blob)) {
        ciphertext = strdup(json_object_get_string(ciphertext_blob));
    }

    json_object_put(resp_obj);
    free(response.data);
    return ciphertext;
}

unsigned char* kms_decrypt(KMSClient *client, const char *ciphertext_blob, size_t *plaintext_len) {
    struct curl_slist *headers = NULL;
    KMSResponse response = {0};
    unsigned char *plaintext = NULL;

    // Prepare JSON request
    json_object *request = json_object_new_object();
    json_object_object_add(request, "CiphertextBlob", json_object_new_string(ciphertext_blob));
    const char *request_str = json_object_to_json_string(request);

    // Set up headers
    headers = curl_slist_append(headers, "Content-Type: application/x-amz-json-1.1");
    headers = curl_slist_append(headers, "X-Amz-Target: TrentService.Decrypt");

    // Set up URL
    char url[256];
    snprintf(url, sizeof(url), "https://kms.%s.amazonaws.com/", client->region);

    // Configure CURL request
    curl_easy_setopt(client->curl, CURLOPT_URL, url);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, request_str);
    curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(client->curl);
    curl_slist_free_all(headers);
    json_object_put(request);

    if (res != CURLE_OK) {
        free(response.data);
        return NULL;
    }

    // Parse response
    json_object *resp_obj = json_tokener_parse(response.data);
    json_object *plaintext_blob;
    
    if (json_object_object_get_ex(resp_obj, "Plaintext", &plaintext_blob)) {
        const char *b64_data = json_object_get_string(plaintext_blob);
        size_t b64_len = strlen(b64_data);
        
        // Allocate buffer for decoded data
        size_t max_decoded_len = ((b64_len * 3) / 4) + 1;
        plaintext = malloc(max_decoded_len);
        if (plaintext) {
            // Base64 decode the response
            EVP_DecodeBlock(plaintext, (const unsigned char*)b64_data, b64_len);
            
            // Calculate actual length (removing padding)
            *plaintext_len = max_decoded_len - 1;
            while (*plaintext_len > 0 && plaintext[*plaintext_len - 1] == 0) {
                (*plaintext_len)--;
            }
        }
    }

    json_object_put(resp_obj);
    free(response.data);
    return plaintext;
}
