#ifndef TOR_DITTOR_IPC_H
#define TOR_DITTOR_IPC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "lib/log/log.h"
#include "lib/malloc/malloc.h"

static inline char *
dittor_ipc_call(int port, const char *message)
{
  int sock = 0;
  struct sockaddr_in serv_addr;
  char buffer[4096] = {0};

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    log_warn(LD_DIR, "Dittor IPC: Failed to create socket descriptor.");
    return NULL;
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
    close(sock);
    return NULL;
  }

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    log_warn(LD_DIR, "Dittor IPC: Connection to Java Sidecar port %d failed.", port);
    close(sock);
    return NULL;
  }

  send(sock, message, strlen(message), 0);
  
  int valread = read(sock, buffer, sizeof(buffer) - 1);
  close(sock);

  if (valread > 0) {
    buffer[valread] = '\0';
    buffer[strcspn(buffer, "\r\n")] = '\0';
    return tor_strdup(buffer);
  }

  return NULL;
}

#endif /* !defined(TOR_DITTOR_IPC_H) */