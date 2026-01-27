#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

#define BUFFER_SIZE 8192
#define DEFAULT_LOCAL_PORT 8443
#define DEFAULT_REMOTE_HOST "127.0.0.1"
#define DEFAULT_REMOTE_PORT 5001

// Global configuration
int LOCAL_PORT_TO_CLIENT = DEFAULT_LOCAL_PORT;
char REMOTE_HOST[256] = DEFAULT_REMOTE_HOST;
int REMOTE_PORT = DEFAULT_REMOTE_PORT;

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);
void url_decode(char *dst, const char *src);
const char* get_content_type(const char *path);

void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            LOCAL_PORT_TO_CLIENT = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            strncpy(REMOTE_HOST, argv[++i], sizeof(REMOTE_HOST) - 1);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            REMOTE_PORT = atoi(argv[++i]);
        }
    }
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    parse_args(argc, argv);

    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Unable to create SSL context\n");
        exit(EXIT_FAILURE);
    }

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Unable to load certificate file\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Unable to load private key file\n");
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Error: Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address
    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("HTTPS server listening on port %d\n", LOCAL_PORT_TO_CLIENT);
    printf("Backend server: %s:%d\n", REMOTE_HOST, REMOTE_PORT);

    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        printf("Accepted connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Create SSL structure for this connection
        SSL *ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;
        }

        SSL_set_fd(ssl, client_socket);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        handle_request(ssl);
        
        // Clean up SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
    }

    close(server_socket);
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    
    return 0;
}

int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if (*src == '%' && ((a = src[1]) && (b = src[2])) && 
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a+b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

const char* get_content_type(const char *path) {
    if (strstr(path, ".html")) {
        return "text/html; charset=UTF-8";
    } else if (strstr(path, ".txt")) {
        return "text/plain; charset=UTF-8";
    } else if (strstr(path, ".jpg") || strstr(path, ".jpeg")) {
        return "image/jpeg";
    } else if (strstr(path, ".png")) {
        return "image/png";
    } else if (strstr(path, ".gif")) {
        return "image/gif";
    } else if (strstr(path, ".m3u8")) {
        return "application/vnd.apple.mpegurl";
    } else if (strstr(path, ".ts")) {
        return "video/mp2t";
    } else {
        return "application/octet-stream";
    }
}

void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // Read request from SSL connection
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    
    if (bytes_read <= 0) {
        int err = SSL_get_error(ssl, bytes_read);
        if (err != SSL_ERROR_ZERO_RETURN) {
            ERR_print_errors_fp(stderr);
        }
        return;
    }

    buffer[bytes_read] = '\0';
    
    // Print the request for debugging
    printf("Received request:\n%s\n", buffer);
    
    // Save the original request for proxying
    char *request_copy = malloc(bytes_read + 1);
    strcpy(request_copy, buffer);
    
    // Parse the request
    char *method = strtok(buffer, " ");
    char *url = strtok(NULL, " ");
    
    if (method == NULL || url == NULL) {
        free(request_copy);
        return;
    }
    
    // Remove leading slash
    char *file_name = url + 1;
    
    // URL decode the filename
    char decoded_filename[512];
    url_decode(decoded_filename, file_name);
    
    // Handle default file (index.html)
    if (strlen(decoded_filename) == 0) {
        strcpy(decoded_filename, "index.html");
    }
    
    // Check if it's a .ts file (video segment) - should be proxied
    if (strstr(decoded_filename, ".ts")) {
        printf("Proxying video segment: %s\n", decoded_filename);
        proxy_remote_file(ssl, request_copy);
    } else if (file_exists(decoded_filename)) {
        printf("Sending local file: %s\n", decoded_filename);
        send_local_file(ssl, decoded_filename);
    } else {
        printf("File not found, proxying: %s\n", decoded_filename);
        proxy_remote_file(ssl, request_copy);
    }
    
    free(request_copy);
}

void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n"
                         "Content-Length: 140\r\n"
                         "\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1><p>The requested file was not found.</p></body></html>";
        SSL_write(ssl, response, strlen(response));
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Determine content type
    const char *content_type = get_content_type(path);

    // Send response header
    char header[512];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "\r\n",
             content_type, file_size);
    
    SSL_write(ssl, header, strlen(header));

    // Send file content
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SSL_write(ssl, buffer, bytes_read);
    }

    fclose(file);
    printf("Successfully sent file: %s (%ld bytes)\n", path, file_size);
}

void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        char *response = "HTTP/1.1 502 Bad Gateway\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n"
                         "\r\n"
                         "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
                         "<body><h1>502 Bad Gateway</h1></body></html>";
        SSL_write(ssl, response, strlen(response));
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to backend server %s:%d\n", REMOTE_HOST, REMOTE_PORT);
        close(remote_socket);
        char *response = "HTTP/1.1 502 Bad Gateway\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n"
                         "\r\n"
                         "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head>"
                         "<body><h1>502 Bad Gateway</h1><p>Backend server unavailable.</p></body></html>";
        SSL_write(ssl, response, strlen(response));
        return;
    }

    // Forward the request to backend server
    send(remote_socket, request, strlen(request), 0);

    // Relay the response from backend to client
    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        SSL_write(ssl, buffer, bytes_read);
    }

    close(remote_socket);
    printf("Successfully proxied request to backend\n");
}