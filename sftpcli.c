// sftpcli.c

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

void receive_file(SSL *ssl, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file %s for writing\n", filename);
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes_received;

    while ((bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, bytes_received, file);
        if (strstr(buffer, "\nTransfer complete") != NULL) {
            break;
        }
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <server_domain> <server_port>\n", argv[0]);
        return 1;
    }

    char *server_domain = argv[1];
    int server_port = atoi(argv[2]);

    SSL_CTX *ctx;
    SSL *ssl;
    int client_socket;
    struct sockaddr_in server_addr;

    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_domain);
    server_addr.sin_port = htons(server_port);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    char buffer[BUFFER_SIZE];
    int bytes_received;

    while ((bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_received] = '\0';
        printf("%s", buffer);

        char command[256];
        fgets(command, sizeof(command), stdin);
        command[strlen(command) - 1] = '\0';

        SSL_write(ssl, command, strlen(command));

        if (strncmp(command, "get ", 4) == 0) {
            receive_file(ssl, command + 4);
            printf("Date and Time: %s\n", __TIME__);
        }

        if (strcmp(command, "exit") == 0) {
            break;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);
    SSL_CTX_free(ctx);

    return 0;
}
