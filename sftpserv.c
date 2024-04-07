// sftpserv.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    SSL_write(ssl, "sftp > ", 7);

    while ((bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_received] = '\0';

        if (strncmp(buffer, "get ", 4) == 0) {
            char filename[256];
            FILE *file;

            sscanf(buffer, "get %s", filename);
            file = fopen(filename, "rb");
            if (file == NULL) {
                SSL_write(ssl, "The file does not exist\n", 25);
            } else {
                fseek(file, 0, SEEK_END);
                long file_size = ftell(file);
                fseek(file, 0, SEEK_SET);

                char *file_data = malloc(file_size);
                fread(file_data, 1, file_size, file);
                fclose(file);

                SSL_write(ssl, file_data, file_size);
                SSL_write(ssl, "\nTransfer complete\n", 19);

                printf("Total characters transferred: %ld\n", file_size);

                free(file_data);
            }
        } else if (strncmp(buffer, "exit", 4) == 0) {
            break;
        } else {
            SSL_write(ssl, "Invalid Command\n", 16);
        }

        SSL_write(ssl, "sftp > ", 7);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <server_port>\n", argv[0]);
        return 1;
    }

    int server_port = atoi(argv[1]);

    SSL_CTX *ctx;
    SSL *ssl;
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        return 1;
    }

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        return 1;
    }

    if (listen(server_socket, 10) == -1) {
        perror("Listen failed");
        return 1;
    }

    printf("SFTP server is listening on port %d...\n", server_port);

    while (1) {
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("Accept failed");
            continue;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            continue;
        }

        printf("Connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        handle_client(ssl);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
    }

    close(server_socket);
    SSL_CTX_free(ctx);

    return 0;
}
