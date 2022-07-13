#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"

#include "print.h"
#include "rand.h"
#include "time.h"

/* A test is fully defined by the attributes pointed in this structure. */
typedef struct {
  /* Test case name */
  const char *name;

  /* Private key */
  const u8 *priv_key;
  u8 priv_key_len;

  /* Message */
  const char *msg;
  u32 msglen;

  /* Expected signature */
  const u8 *exp_sig;
} ec_test_case;

typedef enum {
  ERROR_KEY_IMPORT = 1,
  ERROR_SIG = 2,
  ERROR_SIG_COMP = 3,
  ERROR_VERIF = 4,
} test_err_kind;

static const u8 EXP_SIGLEN = 64;
static const ec_alg_type SIG_ALGO = DECDSA;
static const hash_alg_type HASH_ALGO = SHA256;
// Use it directly, do not reassign it.
// Otherwise there will be some unfathomable error.
static ec_params SECP256R1_EC_PARAMS;

static const u8 decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig[] = {
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd,
    0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa,
    0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7,
    0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1,
    0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4,
    0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8};

static const u8 decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key[] = {
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
    0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
    0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21};

static const u8 test_signature[] = {
    0x68, 0x64, 0xf1, 0xf1, 0xfd, 0x70, 0xe8, 0x8d, 0x8e, 0x50, 0xed,
    0x17, 0xef, 0x8d, 0x78, 0x70, 0x15, 0xfa, 0x88, 0x3b, 0x0c, 0x34,
    0x2e, 0xfc, 0x36, 0xd6, 0x71, 0x48, 0xc2, 0x0f, 0x41, 0x8a, 0x38,
    0x91, 0x76, 0xba, 0x62, 0x24, 0xe2, 0x31, 0xb6, 0xa6, 0xa1, 0x3b,
    0x1c, 0xe5, 0x8a, 0x06, 0xca, 0xa7, 0x58, 0x58, 0xd1, 0x9f, 0x3e,
    0x68, 0xe8, 0x79, 0x0d, 0x67, 0x61, 0x7e, 0xc4, 0xe2};

static const u8 test_message[] = {
    0xf5, 0x5c, 0x2b, 0xdb, 0xac, 0x3e, 0x84, 0x03, 0x72, 0x28, 0xc3,
    0x0c, 0x4d, 0x04, 0x99, 0xf2, 0xfa, 0x95, 0x68, 0x26, 0x62, 0x7d,
    0x4c, 0xcf, 0xed, 0x6a, 0x01, 0xfd, 0xb6, 0x08, 0x68, 0xf1};

static const ec_test_case decdsa_rfc6979_SECP256R1_SHA256_0_test_case = {
    .name = "DECDSA-SHA256/SECP256R1 0",
    .priv_key = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key,
    .priv_key_len =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key),
    .msg = "sample",
    .msglen = 6,
    .exp_sig = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig,
};

static const ec_test_case my_test_case = {
    .name = "DECDSA-SHA256/SECP256R1 0",
    .priv_key = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key,
    .priv_key_len =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key),
    .msg = (const char *)test_message,
    .msglen = 32,
    .exp_sig = test_signature,
};

u8 hex_char_to_integer(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  else
    return 255;
}

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_get_key_pair_from_priv_key_buf(ec_key_pair *kp, const u8 *priv_key,
                                         u8 priv_key_len) {
  return ec_key_pair_import_from_priv_key_buf(kp, &SECP256R1_EC_PARAMS,
                                              priv_key, priv_key_len, SIG_ALGO);
}

ATTRIBUTE_WARN_UNUSED_RET static int secp256r1_sign_message(u8 *sig, u8 siglen,
                                                            ec_key_pair *kp,
                                                            const u8 *m,
                                                            u32 mlen) {
  int ret;

  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(kp != NULL, ret, err);
  MUST_HAVE(m != NULL, ret, err);

  ret = generic_ec_sign(sig, siglen, kp, m, mlen, NULL, SIG_ALGO, HASH_ALGO,
                        NULL, 0);
  EG(ret, err);

  ret = 0;
err:
  return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_verify_signature(u8 *sig, u8 siglen, const ec_pub_key *pub_key,
                           const u8 *m, u32 mlen) {
  int ret;
  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(pub_key != NULL, ret, err);
  MUST_HAVE(m != NULL, ret, err);
  ext_printf("siglen %d, mlen %d, sig_algo %d, hash_algo %d\n", siglen, mlen,
             SIG_ALGO, HASH_ALGO);
  buf_print("signature", sig, siglen);
  buf_print("message", m, mlen);
  ret = ec_verify(sig, siglen, pub_key, m, mlen, SIG_ALGO, HASH_ALGO, NULL, 0);
  if (ret) {
    ret = -1;
    goto err;
  }

  ext_printf("verification succeeded\n");
  ret = 0;
err:
  return ret;
}

/*
 * ECC generic self tests (sign/verify on known test vectors). Returns
 * 0 if given test succeeded, or a non-zero value otherwise. In that
 * case, the value encodes the information on what went wrong as
 * described above.
 */
ATTRIBUTE_WARN_UNUSED_RET static int
ec_sig_known_vector_tests_one(const ec_test_case *c) {
  test_err_kind failed_test = ERROR_KEY_IMPORT;
  u8 sig[EC_MAX_SIGLEN];
  ec_key_pair kp;
  int ret;
  int check = 0;

  MUST_HAVE((c != NULL), ret, err);

  ret = local_memset(&kp, 0, sizeof(kp));
  EG(ret, err);
  ret = local_memset(sig, 0, sizeof(sig));
  EG(ret, err);

  ret = secp256r1_get_key_pair_from_priv_key_buf(&kp, c->priv_key,
                                                 c->priv_key_len);
  if (ret) {
    failed_test = ERROR_KEY_IMPORT;
    goto err;
  }

  pub_key_print("pub_key", &kp.pub_key);
  priv_key_print("priv_key", &kp.priv_key);

  ret = secp256r1_sign_message(sig, EXP_SIGLEN, &kp,
                               (const unsigned char *)c->msg, c->msglen);
  if (ret) {
    failed_test = ERROR_SIG;
    goto err;
  }

  ret = are_equal(sig, c->exp_sig, EXP_SIGLEN, &check);
  EG(ret, err);
  if (!check) {
    ret = -1;
    failed_test = ERROR_SIG_COMP;
    goto err;
  }

  ret = secp256r1_verify_signature(sig, EXP_SIGLEN, &(kp.pub_key),
                                   (const unsigned char *)c->msg, c->msglen);
  if (ret) {
    failed_test = ERROR_VERIF;
    goto err;
  }

  ret = 0;

err:
  if (ret) {
    ext_printf("%s failed: ret %d failed_test %d", __func__, ret, failed_test);
  }
  return ret;
}

int main() {
  int ret;
  ret = import_params(&SECP256R1_EC_PARAMS, &secp256r1_str_params);
  EG(ret, err);
  ret = ec_sig_known_vector_tests_one(
      &decdsa_rfc6979_SECP256R1_SHA256_0_test_case);
  EG(ret, err);
  ret = ec_sig_known_vector_tests_one(&my_test_case);
  EG(ret, err);
err:
  if (ret) {
    ext_printf("ECDSA failed: %d\n", ret);
  }
  return ret;
}
