/*
 *  UDP-TCP SOCKS DNS Tunnel
 *  (C) 2012 jtRIPper
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int   SOCKS_PORT  = 9999;
char *SOCKS_ADDR  = { "127.0.0.1" };
int   LISTEN_PORT = 53;
char *LISTEN_ADDR = { "0.0.0.0" };

#define NUM_DNS 8
char *dns_servers[] = { "8.8.8.8", "8.8.4.4", "208.67.222.222", "208.67.220.220", "198.153.192.1", "198.153.194.1", "156.154.71.1", "156.154.70.1" };

typedef struct {
  char *buffer;
  int length;
} response;

void error(char *e) {
  perror(e);
  exit(1);
}

char *get_value(char *line) {
  char *token, *tmp;
  token = strtok(line, " ");
  for (;;) {
    if ((tmp = strtok(NULL, " ")) == NULL)
      break;
    else
      token = tmp;
  }
  return token;
}

void parse_config(char *file) {
  char line[80], *tmp;

  FILE *f = fopen(file, "r");
  if (!f)
    error("Error opening configuration file");

  while (fgets(line, 80, f) != NULL) {
    if (line[0] == '#')
      continue;

    if(strstr(line, "socks_port") != NULL) {
      SOCKS_PORT = strtol(get_value(line), NULL, 10);
    }
    else if(strstr(line, "socks_addr") != NULL) {
      SOCKS_ADDR = get_value(line);
      tmp = (char*)malloc(strlen(SOCKS_ADDR));
      strcpy(tmp, SOCKS_ADDR);
      SOCKS_ADDR = tmp;
    }
    else if(strstr(line, "listen_addr") != NULL) {
      LISTEN_ADDR = get_value(line);
      tmp = (char*)malloc(strlen(LISTEN_ADDR));
      strcpy(tmp, LISTEN_ADDR);
      LISTEN_ADDR = tmp;
    }
    if(strstr(line, "listen_port") != NULL) {
      LISTEN_PORT = strtol(get_value(line), NULL, 10);
    }
  }
}

void tcp_query(void *query, response *buffer, int len) {
  int sock;
  struct sockaddr_in socks_server;
  char tmp[1024];

  memset(&socks_server, 0, sizeof(socks_server));
  socks_server.sin_family = AF_INET;
  socks_server.sin_port = htons(SOCKS_PORT);
  socks_server.sin_addr.s_addr = inet_addr(SOCKS_ADDR);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) 
    error("Error creating TCP socket");

  if (connect(sock, (struct sockaddr*)&socks_server, sizeof(socks_server)) < 0)
    error("Error connecting to proxy");
  
  // socks handshake
  send(sock, "\x05\x01\x00", 3, 0);
  recv(sock, tmp, 1024, 0);

  // select random dns server
  in_addr_t remote_dns = inet_addr(dns_servers[rand() % (NUM_DNS - 1)]);
  memcpy(tmp, "\x05\x01\x00\x01", 4);
  memcpy(tmp + 4, &remote_dns, 4);
  memcpy(tmp + 8, "\x00\x35", 2);
  send(sock, tmp, 10, 0);

  recv(sock, tmp, 1024, 0);

  // forward dns query
  send(sock, query, len, 0);
  buffer->length = recv(sock, buffer->buffer, 2048, 0);
}

int udp_listener() {
  int sock;
  char len, *query;
  response *buffer = (response*)malloc(sizeof(response));
  struct sockaddr_in dns_listener, dns_client;

  buffer->buffer = malloc(2048);

  memset(&dns_listener, 0, sizeof(dns_listener));
  dns_listener.sin_family = AF_INET;
  dns_listener.sin_port = htons(LISTEN_PORT);
  dns_listener.sin_addr.s_addr = inet_addr(LISTEN_ADDR);

  // create our udp listener
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    error("Error setting up dns proxy");

  if(bind(sock, (struct sockaddr*)&dns_listener, sizeof(dns_listener)) < 0)
    error("Error binding on dns proxy");

  socklen_t dns_client_size = sizeof(struct sockaddr_in);

  while(1) {
    // receive a dns request from the client
    len = recvfrom(sock, buffer->buffer, 2048, 0, (struct sockaddr *)&dns_client, &dns_client_size);

    // fork so we can keep receiving requests
    if (fork() != 0) { continue; }

    // the tcp query requires the length to precede the packet, so we put the length there
    query = malloc(len + 3);
    query[0] = 0;
    query[1] = len;
    memcpy(query + 2, buffer->buffer, len);

    // forward the packet to the tcp dns server
    tcp_query(query, buffer, len + 2);

    // send the reply back to the client (minus the length at the beginning)
    sendto(sock, buffer->buffer + 2, buffer->length - 2, 0, (struct sockaddr *)&dns_client, sizeof(dns_client));

    free(buffer->buffer);
    free(buffer);
    free(query);

    exit(0);
  }
}

int main(int argc, char *argv[]) {
  if (argc == 1)
    parse_config("dns.conf");
  else if (argc == 2) {
    if (!strcmp(argv[1], "-h")) {
      printf("Usage: %s [options]\n", argv[0]);
      printf(" * With no parameters, the configuration file is read from 'dns.conf'.\n\n");
      printf(" -n          -- No configuration file (socks: 127.0.0.1:9999, listener: 0.0.0.0:53).\n");
      printf(" -h          -- Print this message and exit.\n");
      printf(" config_file -- Read from specified configuration file.\n\n");
      printf(" * The configuration file should contain any of the following options (and ignores lines that begin with '#'):\n");
      printf("   * socks_addr  -- socks listener address\n");
      printf("   * socks_port  -- socks listener port\n");
      printf("   * listen_addr -- address for the dns proxy to listen on\n");
      printf("   * listen_port -- port for the dns proxy to listen on (most cases 53)\n\n");
      printf(" * Configuration directives should be of the format:\n");
      printf("   option = value\n\n");
      printf(" * Any non-specified options will be set to their defaults:\n");
      printf("   * socks_addr = 127.0.0.1\n");
      printf("   * socks_port = 9999\n");
      printf("   * listen_addr = 0.0.0.0\n");
      printf("   * listen_port = 53\n");
      exit(0);
    }
    else {
      parse_config(argv[1]);
    }
  }

  // daemonize the process.
  if(fork() != 0) { return; }
  if(fork() != 0) { return; }

  srand(time(NULL));

  // start the dns proxy
  udp_listener();
}
