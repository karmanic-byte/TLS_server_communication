#include <openssl/ssl.h>
#include <iostream>

int main() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx) {
        std::cout << "OpenSSL initialized successfully!" << std::endl;
        SSL_CTX_free(ctx);
    } else {
        std::cout << "Failed to initialize OpenSSL" << std::endl;
    }
    return 0;
}