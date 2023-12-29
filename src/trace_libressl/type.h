#pragma once

#define kInvalidFd -1 
#define MAX_DATA_SIZE 1024 * 8

enum data_event_type {
    kSSL_Read,
    kSSL_Write
};

struct ssl_data_event_t {
  enum data_event_type type;
  uint64_t timestamp_ns;
  uint32_t pid;
  int32_t fd;
  char data[MAX_DATA_SIZE];
  char common[16];
  int32_t data_len;
};

struct data_args_t {
 const char *buf;
 int32_t fd;
};

struct libressl_symaddr_t {
    int32_t SSL_rbio_offset; // struct ssl_st rbio
    int32_t RBIO_num_offset; // struct bio_st num
};

struct libretls_symaddr_t {
    int32_t TLS_socket; // struct tls socket
};