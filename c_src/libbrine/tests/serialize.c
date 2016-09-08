#include <string.h>
#include <memory.h>
#include "test.h"
#include "brine.h"

SUITE(serialize) {
  SETUP({
      brine_init(NULL);
      return true;
    });

  TEST(to_blob, {
      brine_keypair_s *keypair = brine_new_keypair();
      unsigned char *blob = (unsigned char *) malloc(BRINE_BLOB_SZ);
      size_t bloblen = BRINE_BLOB_SZ;
      ASSERT_(keypair != NULL);
      ASSERT_(!brine_serialize_keypair(NULL, blob, bloblen));
      ASSERT_(!brine_serialize_keypair(keypair, NULL, bloblen));
      ASSERT_(!brine_serialize_keypair(keypair, blob, 9999999999));
      ASSERT_(brine_serialize_keypair(keypair, blob, bloblen));
    });

  TEST(from_blob, {
      brine_keypair_s *keypair = brine_new_keypair();
      brine_keypair_s keypair1;
      unsigned char *blob = (unsigned char *) malloc(BRINE_BLOB_SZ);
      size_t bloblen = BRINE_BLOB_SZ;
      ASSERT_(keypair != NULL);
      ASSERT_(brine_serialize_keypair(keypair, blob, bloblen));
      ASSERT_(!brine_deserialize_keypair(NULL, bloblen, &keypair1));
      ASSERT_(!brine_deserialize_keypair(blob, 12389, &keypair1));
      ASSERT_(!brine_deserialize_keypair(blob, bloblen, NULL));
      ASSERT_(brine_deserialize_keypair(blob, bloblen, &keypair1));
      ASSERT_(keypair1.public_key[BRINE_PUBKEY_SZ - 1] != '\0');
      ASSERT_(keypair1.private_key[BRINE_PRIVKEY_SZ - 1] != '\0');
      for (int i = 0; i < BRINE_PUBKEY_SZ; i++) {
        ASSERT_(keypair->public_key[i] == keypair1.public_key[i]);
      }
      for (int i = 0; i < BRINE_PRIVKEY_SZ; i++) {
        ASSERT_(keypair->private_key[i] == keypair1.private_key[i]);
      }
    });

}
SUITE_END();

