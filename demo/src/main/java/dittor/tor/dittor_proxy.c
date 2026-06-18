#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

char* dittorProxy(int port, const char* message) {
    int sock = 0;
    struct sockaddr_in serverAddress;
    char buffer[2048] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return NULL;
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);

    if (inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) <= 0) {
        return NULL;
    }

    if (connect(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        return NULL;
    }

    send(sock, message, strlen(message), 0);
    int valread = read(sock, buffer, 2047);
    close(sock);

    if (valread > 0) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        return strdup(buffer);
    }

    return NULL;
}

int main() {
    printf("Testing proxy socket connection...\n");
    char* response = dittorProxy(8081, "VALIDATE test_context|pk|nym|zkp|challenge|response\n");
    if (response) {
        printf("Server responded: %s\n", response);
        free(response);
    } else {
        printf("Failed to connect to Java server.\n");
    }
    return 0;
}