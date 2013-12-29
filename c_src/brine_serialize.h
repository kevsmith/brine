#ifndef BRINE_SERIALIZE_H
#define BRINE_SERIALIZE_H

#include <stdbool.h>
#include <stdint.h>

// Key & signature constants
#define BRINE_SEED_SZ 32
#define BRINE_PUBKEY_SZ 32
#define BRINE_PRIVKEY_SZ 64
#define BRINE_SIG_SZ 32
#define BRINE_BLOB_HEADER_SZ 10
#define BRINE_BLOB_SZ BRINE_PRIVKEY_SZ + BRINE_PUBKEY_SZ + BRINE_BLOB_HEADER_SZ
#define BRINE_BLOB_VERSION 0x01

typedef struct {
  unsigned char private[BRINE_PRIVKEY_SZ];
  unsigned char public[BRINE_PUBKEY_SZ];
} brine_keypair_s;

void brine_serializer_init();

bool brine_keypair_to_binary(brine_keypair_s *keypair, unsigned char *buf, size_t bufsz);
bool brine_binary_to_keypair(brine_keypair_s *keypair, unsigned char *buf, size_t bufsz);

#endif
