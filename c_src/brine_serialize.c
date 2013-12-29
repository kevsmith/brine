#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <byteswap.h>
#include <arpa/inet.h>
#include "blake2.h"
#include "ed25519.h"
#include "brine_serialize.h"

typedef uint32_t(*byte_swapper32)(uint32_t value);
typedef uint16_t(*byte_swapper16)(uint16_t value);

static byte_swapper32 byte_swap32;
static byte_swapper16 byte_swap16;

#define SHIFT(v, a) (((uint32_t) v) << a)

static uint32_t big_endian_swapper32(uint32_t value) {
  return value;
}

static uint32_t little_endian_swapper32(uint32_t value) {
  return bswap_32(value);
}

static uint16_t big_endian_swapper16(uint16_t value) {
  return value;
}

static uint16_t little_endian_swapper16(uint16_t value) {
  return bswap_16(value);
}


static void write_array(unsigned char *dest, const unsigned char *src, size_t len) {
  int destidx = 0;
  for (int i = 0; i < len; i += 4) {
    uint32_t value = byte_swap32(SHIFT(src[i + 3], 24) | SHIFT(src[i + 2], 16) |
                               SHIFT(src[i + 1], 8) | src[i]);
    memcpy(&dest[destidx], &value, sizeof(uint32_t));
    destidx += sizeof(uint32_t);
  }
}

static void read_array(uint8_t *dest, const unsigned char *src, size_t len) {
  int destidx = 0;
  uint32_t value = 0;
  for (int i = 0; i < len; i += 4) {
    memcpy(&value, &src[i], 4);
    value = byte_swap32(value);
    memcpy(&dest[destidx], &value, sizeof(uint32_t));
    destidx += sizeof(uint32_t);
  }
}

void brine_serializer_init() {
  if (htons(47) == 47) {
    byte_swap32 = big_endian_swapper32;
    byte_swap16 = big_endian_swapper16;
  }
  else {
    byte_swap32 = little_endian_swapper32;
    byte_swap16 = little_endian_swapper16;
  }
}

bool brine_keypair_to_binary(brine_keypair_s *keypair, unsigned char *buf, size_t bufsz) {
  if (bufsz != BRINE_BLOB_SZ) {
    return false;
  }

  unsigned char hash_key[32];
  uint8_t keypair_hash[8];
  blake2b_state bs;
  int idx = 0;
  uint16_t version = byte_swap16(BRINE_BLOB_VERSION);

  // Generate key exchange secret to use as hash key
  ed25519_key_exchange(hash_key, keypair->public, keypair->private);
  // Generate blake2 hash of keypair w/key exchange
  blake2b_init_key(&bs, 8, hash_key, 32);
  blake2b_update(&bs, keypair->private, BRINE_PRIVKEY_SZ);
  blake2b_update(&bs, keypair->public, BRINE_PUBKEY_SZ);
  blake2b_final(&bs, keypair_hash, 8);

  // Write blob version
  memcpy(buf, &version, sizeof(uint16_t));
  idx += sizeof(uint16_t);
  write_array(&buf[idx], keypair_hash, 8);
  idx += 8;
  write_array(&buf[idx], keypair->private, BRINE_PRIVKEY_SZ);
  idx += BRINE_PRIVKEY_SZ;
  write_array(&buf[idx], keypair->public, BRINE_PUBKEY_SZ);
  return true;
}

bool brine_binary_to_keypair(brine_keypair_s *keypair, unsigned char *buf, size_t bufsz) {
  if (bufsz != BRINE_BLOB_SZ) {
    return false;
  }

  unsigned char hash_key[32];
  uint8_t keypair_hash[8];
  uint8_t verify_hash[8];
  blake2b_state bs;
  int idx = 0;

  // Read and verify blob version
  uint16_t version = byte_swap16((((uint16_t) buf[1]) << 8) | (((uint16_t) buf[0])));
  if (version != BRINE_BLOB_VERSION) {
    return false;
  }
  idx += sizeof(uint16_t);
  // Read keypair "checksum" hash
  read_array(keypair_hash, &buf[idx], 8);
  idx += 8;
  // Read private key
  read_array(keypair->private, &buf[idx], BRINE_PRIVKEY_SZ);
  idx += BRINE_PRIVKEY_SZ;
  // Read public key
  read_array(keypair->public, &buf[idx], BRINE_PUBKEY_SZ);

  // verify keypair is correct
  ed25519_key_exchange(hash_key, keypair->public, keypair->private);
  blake2b_init_key(&bs, 8, hash_key, 32);
  blake2b_update(&bs, keypair->private, BRINE_PRIVKEY_SZ);
  blake2b_update(&bs, keypair->public, BRINE_PUBKEY_SZ);
  blake2b_final(&bs, verify_hash, 8);
  for (int i = 0; i < 8; i++) {
    if (keypair_hash[i] != verify_hash[i]) {
      memset(keypair->private, 0, BRINE_PRIVKEY_SZ);
      memset(keypair->public, 0, BRINE_PUBKEY_SZ);
      return false;
    }
  }
  return true;
}
