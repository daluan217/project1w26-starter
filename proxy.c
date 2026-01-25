#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

// Global variables for command-line arguments
int local_port = LOCAL_PORT_TO_CLIENT;
char remote_host[256] = REMOTE_HOST;
int remote_port = REMOTE_PORT;

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

// Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    int opt;
    char *endptr;
    long val;
    
    while ((opt = getopt(argc, argv, "b:r:p:")) != -1) {
        switch (opt) {
            case 'b':
                val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val <= 0 || val > 65535) {
                    fprintf(stderr, "Error: Invalid port number for -b: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                local_port = (int)val;
                break;
            case 'r':
                strncpy(remote_host, optarg, sizeof(remote_host) - 1);
                remote_host[sizeof(remote_host) - 1] = '\0';
                break;
            case 'p':
                val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val <= 0 || val > 65535) {
                    fprintf(stderr, "Error: Invalid port number for -p: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                remote_port = (int)val;
                break;
            default:
                fprintf(stderr, "Usage: %s [-b <port>] [-r <host>] [-p <port>]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // TODO: Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // TODO: Create SSL context and load certificate/private key files
    // Files: "server.crt" and "server.key"
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    
    if (ssl_ctx == NULL) {
        fprintf(stderr, "Error: SSL context not initialized\n");
        exit(EXIT_FAILURE);
    }

    // Load certificate file
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error: Could not load certificate file\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load private key file
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error: Could not load private key file\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Error: Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(local_port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (listen(server_socket, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", local_port);

    while (1) {
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // TODO: Create SSL structure for this connection and perform SSL handshake
        SSL *ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            fprintf(stderr, "Error: Could not create SSL object\n");
            close(client_socket);
            continue;
        }

        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "Error: SSL handshake failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        if (ssl != NULL) {
            handle_request(ssl);
        }
        
        // TODO: Clean up SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        
        close(client_socket);
    }

    close(server_socket);
    // TODO: Clean up SSL context
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // TODO: Read request from SSL connection
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        fprintf(stderr, "Error: SSL read failed\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    
    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);
    printf("Received request: %s\n", request);
    
    char *method = strtok(request, " ");
    char *file_name_raw = strtok(NULL, " ");
    char *http_version = strtok(NULL, " ");
    
    if (method == NULL || strcmp(method, "GET") != 0) {
        fprintf(stderr, "Error: Only GET method is supported\n");
        char *response = "HTTP/1.1 405 Method Not Allowed\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><body><h1>405 Method Not Allowed</h1></body></html>";
        SSL_write(ssl, response, strlen(response));
        free(request);
        return;
    }
    
    if (http_version == NULL || (strcmp(http_version, "HTTP/1.0") != 0 && strcmp(http_version, "HTTP/1.1") != 0)) {
        fprintf(stderr, "Error: Unsupported HTTP version\n");
        char *response = "HTTP/1.1 505 HTTP Version Not Supported\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><body><h1>505 HTTP Version Not Supported</h1></body></html>";
        SSL_write(ssl, response, strlen(response));
        free(request);
        return;
    }
    
    printf("HTTP Method: %s, HTTP Version: %s\n", method, http_version);
    
    // Handle file path - remove leading slash
    char file_name[BUFFER_SIZE];
    if (file_name_raw && strlen(file_name_raw) > 0) {
        strcpy(file_name, file_name_raw);
        // Remove leading slash
        if (file_name[0] == '/') {
            memmove(file_name, file_name + 1, strlen(file_name));
        }
        // If empty after removing slash, use index.html
        if (strlen(file_name) == 0) {
            strcpy(file_name, "index.html");
        }
    } else {
        strcpy(file_name, "index.html");
    }

    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
    
    free(request);
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";
        // TODO: Send response via SSL
        SSL_write(ssl, response, strlen(response));
        
        return;
    }

    char *response;
    if (strstr(path, ".html")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    } else if (strstr(path, ".m3u8")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/vnd.apple.mpegurl\r\n\r\n";
    } else if (strstr(path, ".ts")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: video/mp2t\r\n\r\n";
    } else if (strstr(path, ".jpg") || strstr(path, ".jpeg")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: image/jpeg\r\n\r\n";
    } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    }

    // TODO: Send response header and file content via SSL
    SSL_write(ssl, response, strlen(response));

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // TODO: Send file data via SSL
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            fprintf(stderr, "Error: SSL write failed\n");
            break;
        }
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, remote_host, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(remote_port);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // TODO: Forward response to client via SSL
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            fprintf(stderr, "Error: SSL write failed\n");
            break;
        }
    }

    close(remote_socket);
}
