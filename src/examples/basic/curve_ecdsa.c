#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"

/* We include the printf external dependency for printf output */
#include "print.h"
/* We include the time external dependency for performance measurement */
#include "time.h"

#include "rand.h"

/* A test is fully defined by the attributes pointed in this structure. */
typedef struct {
  /* Test case name */
  const char *name;

  /* Curve params */
  const ec_str_params *ec_str_p;

  /* Private key */
  const u8 *priv_key;
  u8 priv_key_len;

  /* Function returning a fixed random value */
  int (*nn_random)(nn_t out, nn_src_t q);

  /* Hash function */
  hash_alg_type hash_type;

  /* Message */
  const char *msg;
  u32 msglen;

  /* Expected signature and associated length */
  ec_alg_type sig_type;
  const u8 *exp_sig;
  u8 exp_siglen;

  /* Optional ancillary data */
  const u8 *adata;
  u16 adata_len;
} ec_test_case;

typedef enum {
  ERROR_KEY_IMPORT = 1,
  ERROR_SIG = 2,
  ERROR_SIG_COMP = 3,
  ERROR_VERIF = 4,
  ERROR_ECDH = 5,
  ERROR_ECDH_COMP = 6,
} test_err_kind;

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
    0xd3, 0xf0, 0x2e, 0x8b, 0x5b, 0x44, 0x78, 0xed, 0x7a, 0xcd, 0x23,
    0xec, 0x0b, 0x0e, 0x31, 0x34, 0xc4, 0x2c, 0x0c, 0x7e, 0x6d, 0xfa,
    0x7c, 0xcf, 0xf0, 0xcc, 0xf0, 0xf2, 0xf6, 0x35, 0xfe, 0xe7, 0xd8,
    0x6c, 0xb2, 0x49, 0x79, 0xe2, 0x2e, 0xc9, 0xfe, 0x45, 0x3f, 0x65,
    0xf4, 0x6b, 0x29, 0x14, 0x42, 0x81, 0xe1, 0xff, 0x45, 0xbc, 0x31,
    0x5a, 0x99, 0xdc, 0x4c, 0x09, 0x8d, 0x49, 0xd2, 0x40};

static const u8 test_message[] = {
    0xae, 0xc3, 0x66, 0x75, 0xe2, 0xb7, 0xb5, 0x5a, 0xd3, 0xc7, 0x5f,
    0xc2, 0xb3, 0x0a, 0x18, 0x64, 0x35, 0x5a, 0xe0, 0x26, 0xff, 0x26,
    0x1e, 0x9b, 0x00, 0x53, 0x11, 0xc9, 0xe4, 0x91, 0xc3, 0x26};

static const ec_test_case decdsa_rfc6979_SECP256R1_SHA256_0_test_case = {
    .name = "DECDSA-SHA256/SECP256R1 0",
    .ec_str_p = &secp256r1_str_params,
    .priv_key = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key,
    .priv_key_len =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key),
    .nn_random = NULL,
    .hash_type = HASH_ALGO,
    .msg = "sample",
    .msglen = 6,
    .sig_type = SIG_ALGO,
    .exp_sig = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig,
    .exp_siglen =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_expected_sig),
    .adata = NULL,
    .adata_len = 0};

static const ec_test_case my_test_case = {
    .name = "DECDSA-SHA256/SECP256R1 0",
    .ec_str_p = &secp256r1_str_params,
    .priv_key = decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key,
    .priv_key_len =
        sizeof(decdsa_rfc6979_SECP256R1_SHA256_0_test_vector_priv_key),
    .nn_random = NULL,
    .hash_type = HASH_ALGO,
    .msg = (const char *)test_message,
    .msglen = 32,
    .sig_type = SIG_ALGO,
    .exp_sig = test_signature,
    .exp_siglen = sizeof(test_signature),
    .adata = NULL,
    .adata_len = 0};

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_verify_signature(u8 *sig, u8 siglen, const ec_pub_key *pub_key,
                           const u8 *m, u32 mlen) {
  int ret;
  MUST_HAVE(sig != NULL, ret, err);
  ext_printf("siglen %d, mlen %d, sig_algo %d, hash_algo %d\n", siglen, mlen,
             DECDSA, SHA256);
  buf_print("signature", sig, siglen);
  buf_print("message", m, mlen);
  ret = ec_verify(sig, siglen, pub_key, m, mlen, DECDSA, SHA256, NULL, 0);
  if (ret) {
    ret = -1;
    goto err;
  }

  ret = 0;
err:
  return ret;
}

ATTRIBUTE_WARN_UNUSED_RET static int ec_test_verify(u8 *sig, u8 siglen,
                                                    const ec_pub_key *pub_key,
                                                    const ec_test_case *c) {
  return secp256r1_verify_signature(sig, siglen, pub_key, (const u8 *)(c->msg),
                                    c->msglen);
}

ATTRIBUTE_WARN_UNUSED_RET static int secp256r1_sign_message(u8 *sig, u8 siglen,
                                                            ec_key_pair *kp,
                                                            const u8 *m,
                                                            u32 mlen) {
  int ret;

  MUST_HAVE(sig != NULL, ret, err);
  MUST_HAVE(kp != NULL, ret, err);
  MUST_HAVE(m != NULL, ret, err);

  ret =
      generic_ec_sign(sig, siglen, kp, m, mlen, NULL, DECDSA, SHA256, NULL, 0);
  EG(ret, err);

  ret = 0;
err:
  return ret;
}

/*
 * Those functions respectively perform signature and verification tests
 * based the content of a given test case.
 */
ATTRIBUTE_WARN_UNUSED_RET static int
ec_test_sign(u8 *sig, u8 siglen, ec_key_pair *kp, const ec_test_case *c) {
  return secp256r1_sign_message(sig, siglen, kp, (const u8 *)(c->msg),
                                c->msglen);
}

ATTRIBUTE_WARN_UNUSED_RET static int
secp256r1_recover_public_key_from_signature(ec_pub_key *pub_key1,
                                            ec_pub_key *pub_key2, const u8 *sig,
                                            u8 siglen, const u8 *hash,
                                            u8 hsize) {
  return __ecdsa_public_key_from_sig(pub_key1, pub_key2, &SECP256R1_EC_PARAMS,
                                     sig, siglen, hash, hsize, SIG_ALGO);
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
  const u8 buf_size = 64;
  u8 temp_buf[buf_size];
  u8 siglen;
  int ret;
  int check = 0;

  MUST_HAVE((c != NULL), ret, err);

  ret = local_memset(&kp, 0, sizeof(kp));
  EG(ret, err);
  ret = local_memset(sig, 0, sizeof(sig));
  EG(ret, err);
  ret = local_memset(&temp_buf, 0, buf_size);
  EG(ret, err);

  /* Regular import if not EdDSA */
  ret = ec_key_pair_import_from_priv_key_buf(
      &kp, &SECP256R1_EC_PARAMS, c->priv_key, c->priv_key_len, c->sig_type);
  if (ret) {
    failed_test = ERROR_KEY_IMPORT;
    goto err;
  }

  pub_key_print("pub_key", &kp.pub_key);
  priv_key_print("priv_key", &kp.priv_key);
  ret = ec_pub_key_export_to_aff_buf(&kp.pub_key, (u8 *)&temp_buf, buf_size);
  if (ret) {
    ext_printf("export pub key affine failed %d", ret);
    failed_test = ERROR_KEY_IMPORT;
    goto err;
  }
  priv_key_print("priv_key", &kp.priv_key);
  buf_print("public aff key", (u8 *)&temp_buf, buf_size);

  siglen = c->exp_siglen;
  ret = ec_test_sign(sig, siglen, &kp, c);
  if (ret) {
    failed_test = ERROR_SIG;
    goto err;
  }

  ret = are_equal(sig, c->exp_sig, siglen, &check);
  EG(ret, err);
  if (!check) {
    ret = -1;
    failed_test = ERROR_SIG_COMP;
    goto err;
  }

  ret = ec_test_verify(sig, siglen, &(kp.pub_key), c);
  if (ret) {
    failed_test = ERROR_VERIF;
    goto err;
  }

  /* Try a public key recovery from the signature and the message.
   * This is only possible for ECDSA.
   */
  {
    struct ec_sign_context sig_ctx;
    u8 digest[MAX_DIGEST_SIZE] = {0};
    u8 digestlen;
    ec_pub_key pub_key1;
    ec_pub_key pub_key2;
    nn_src_t cofactor = &(SECP256R1_EC_PARAMS.ec_gen_cofactor);
    int cofactorisone;
    const u8 *input[2] = {(const u8 *)(c->msg), NULL};
    u32 ilens[2] = {c->msglen, 0};
    /* Initialize our signature context only for the hash */
    ret = ec_sign_init(&sig_ctx, &kp, c->sig_type, c->hash_type, c->adata,
                       c->adata_len);
    EG(ret, err);
    /* Perform the hash of the data ourselves */
    ret = hash_mapping_callbacks_sanity_check(sig_ctx.h);
    EG(ret, err);
    ret = sig_ctx.h->hfunc_scattered(input, ilens, digest);
    EG(ret, err);
    digestlen = sig_ctx.h->digest_size;
    MUST_HAVE(digestlen <= sizeof(digest), ret, err);
    /* Check the cofactor */
    ret = nn_isone(cofactor, &cofactorisone);
    EG(ret, err);
    /* Compute the two possible public keys */
    ret = secp256r1_recover_public_key_from_signature(
        &pub_key1, &pub_key2, sig, siglen, digest, digestlen);
    if (ret) {
      ret = 0;
      check = -1;
      goto pubkey_recovery_warning;
    }
    /* Check equality with one of the two keys */
    ret = prj_pt_cmp(&(pub_key1.y), &(kp.pub_key.y), &check);
    EG(ret, err);
    if (check) {
      ret = prj_pt_cmp(&(pub_key2.y), &(kp.pub_key.y), &check);
      EG(ret, err);
    }
  pubkey_recovery_warning:
    if (check && cofactorisone) {
      ext_printf("[~] Warning: ECDSA recovered public key differs from "
                 "real one ...");
      ext_printf("This can happen with very low probability. Please check "
                 "the trace:\n");
      pub_key_print("pub_key1", &pub_key1);
      pub_key_print("pub_key2", &pub_key2);
      pub_key_print("pub_key", &(kp.pub_key));
      buf_print("digest", digest, digestlen);
      buf_print("sig", sig, siglen);
    }
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
