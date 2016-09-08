#include "brine.h"
#include "test.h"

SUITE(keypair) {
  SETUP({
      brine_init(NULL);
      return true;
    });

  TEST(new_keypair, {
      brine_keypair_s *keypair = brine_new_keypair();
      ASSERT_(keypair != NULL);
      ASSERT_(keypair->public_key[BRINE_PUBKEY_SZ - 1] != '\0');
      ASSERT_(keypair->private_key[BRINE_PRIVKEY_SZ - 1] != '\0');
    });

  TEST(init_keypair, {
      brine_keypair_s keypair;
      ASSERT_(brine_init_keypair(&keypair));
      ASSERT_(keypair.public_key[BRINE_PUBKEY_SZ - 1] != '\0');
      ASSERT_(keypair.private_key[BRINE_PRIVKEY_SZ - 1] != '\0');
    });

  TEST(equal_keypair, {
      brine_keypair_s *k1 = brine_new_keypair();
      brine_keypair_s *k2 = brine_new_keypair();
      ASSERT_(!brine_keypairs_are_identical(NULL, k1));
      ASSERT_(!brine_keypairs_are_identical(k1, NULL));
      ASSERT_(!brine_keypairs_are_identical(NULL, NULL));
      ASSERT_(brine_keypairs_are_identical(k1, k1));
      ASSERT_(brine_keypairs_are_identical(k2, k2));
      ASSERT_(!brine_keypairs_are_identical(k1, k2));
    });
}
SUITE_END();
