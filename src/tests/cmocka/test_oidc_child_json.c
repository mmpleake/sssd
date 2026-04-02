/*
    SSSD

    Unit tests for oidc_child_json.c — onPremisesImmutableId decode

    Authors:
        Pacific Northwest National Laboratory (PNNL)

    Copyright (C) 2026 Battelle Memorial Institute

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <talloc.h>
#include <jansson.h>

#include "tests/common.h"

/*
 * Include the source file directly so we can test static functions.
 * This is a standard pattern in the SSSD cmocka test suite.
 */
#include "src/oidc_child/oidc_child_json.c"

/* -----------------------------------------------------------------------
 * Test data
 *
 * These values were captured from a real Azure AD Connect environment:
 *
 *   AD objectGUID:              d79f979f-ed1b-4202-b7ec-704a6643f10b
 *   Entra onPremisesImmutableId: n5ef1xvtAkK37HBKZkPxCw==
 *   Entra id (cloud UUID):      ad48cfec-a23d-4851-bb2b-90fd0ac38320
 *
 * The base64 value decodes to 16 raw bytes which, when interpreted as a
 * Microsoft GUID in bytes_le format, produce the AD objectGUID.
 * ----------------------------------------------------------------------- */
#define TEST_ONPREM_IMMUTABLE_ID  "n5ef1xvtAkK37HBKZkPxCw=="
#define TEST_AD_OBJECTGUID        "d79f979f-ed1b-4202-b7ec-704a6643f10b"
#define TEST_ENTRA_ID             "ad48cfec-a23d-4851-bb2b-90fd0ac38320"

/* Raw bytes of the GUID after base64 decode (16 bytes) */
static const uint8_t expected_guid_bytes[16] = {
    0x9f, 0x97, 0x9f, 0xd7,  /* group 1: LE -> d79f979f */
    0x1b, 0xed,              /* group 2: LE -> ed1b */
    0x02, 0x42,              /* group 3: LE -> 0242 */
    0xb7, 0xec,              /* group 4: BE -> b7ec */
    0x70, 0x4a, 0x66, 0x43, 0xf1, 0x0b  /* group 5: BE -> 704a6643f10b */
};

/* -----------------------------------------------------------------------
 * base64_decode_char() tests
 * ----------------------------------------------------------------------- */

static void test_base64_decode_char_uppercase(void **state)
{
    assert_int_equal(base64_decode_char('A'), 0);
    assert_int_equal(base64_decode_char('Z'), 25);
    assert_int_equal(base64_decode_char('M'), 12);
}

static void test_base64_decode_char_lowercase(void **state)
{
    assert_int_equal(base64_decode_char('a'), 26);
    assert_int_equal(base64_decode_char('z'), 51);
    assert_int_equal(base64_decode_char('n'), 39);
}

static void test_base64_decode_char_digits(void **state)
{
    assert_int_equal(base64_decode_char('0'), 52);
    assert_int_equal(base64_decode_char('9'), 61);
    assert_int_equal(base64_decode_char('5'), 57);
}

static void test_base64_decode_char_special(void **state)
{
    assert_int_equal(base64_decode_char('+'), 62);
    assert_int_equal(base64_decode_char('/'), 63);
}

static void test_base64_decode_char_invalid(void **state)
{
    assert_int_equal(base64_decode_char('='), -1);
    assert_int_equal(base64_decode_char(' '), -1);
    assert_int_equal(base64_decode_char('\0'), -1);
    assert_int_equal(base64_decode_char('!'), -1);
    assert_int_equal(base64_decode_char('-'), -1);  /* base64url, not base64 */
    assert_int_equal(base64_decode_char('_'), -1);  /* base64url, not base64 */
}

/* -----------------------------------------------------------------------
 * base64_decode() tests
 * ----------------------------------------------------------------------- */

static void test_base64_decode_known_guid(void **state)
{
    uint8_t output[16];
    ssize_t len;

    len = base64_decode(TEST_ONPREM_IMMUTABLE_ID, output, sizeof(output));
    assert_int_equal(len, 16);
    assert_memory_equal(output, expected_guid_bytes, 16);
}

static void test_base64_decode_null_input(void **state)
{
    uint8_t output[16];
    ssize_t len;

    len = base64_decode(NULL, output, sizeof(output));
    assert_int_equal(len, -1);
}

static void test_base64_decode_empty_string(void **state)
{
    uint8_t output[16];
    ssize_t len;

    len = base64_decode("", output, sizeof(output));
    assert_int_equal(len, 0);
}

static void test_base64_decode_output_too_small(void **state)
{
    uint8_t output[4];  /* Too small for 16-byte GUID */
    ssize_t len;

    len = base64_decode(TEST_ONPREM_IMMUTABLE_ID, output, sizeof(output));
    assert_int_equal(len, -1);
}

static void test_base64_decode_no_padding(void **state)
{
    /* "AQID" decodes to { 0x01, 0x02, 0x03 } — no padding needed */
    uint8_t output[3];
    ssize_t len;

    len = base64_decode("AQID", output, sizeof(output));
    assert_int_equal(len, 3);
    assert_int_equal(output[0], 0x01);
    assert_int_equal(output[1], 0x02);
    assert_int_equal(output[2], 0x03);
}

static void test_base64_decode_with_plus_and_slash(void **state)
{
    /* "ab+/" decodes to { 0x69, 0xbf, 0xbf } — exercises + and / chars */
    uint8_t output[3];
    ssize_t len;

    len = base64_decode("ab+/", output, sizeof(output));
    assert_int_equal(len, 3);
    assert_int_equal(output[0], 0x69);
    assert_int_equal(output[1], 0xbf);
    assert_int_equal(output[2], 0xbf);
}

/* -----------------------------------------------------------------------
 * decode_onprem_immutable_id() tests
 * ----------------------------------------------------------------------- */

static void test_decode_onprem_immutable_id_success(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "id",
                        json_string(TEST_ENTRA_ID));
    json_object_set_new(userinfo, "onPremisesImmutableId",
                        json_string(TEST_ONPREM_IMMUTABLE_ID));

    const char *result = decode_onprem_immutable_id(tmp_ctx, userinfo);
    assert_non_null(result);
    assert_string_equal(result, TEST_AD_OBJECTGUID);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

static void test_decode_onprem_immutable_id_missing(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* Cloud-only user: no onPremisesImmutableId field */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "id",
                        json_string(TEST_ENTRA_ID));

    const char *result = decode_onprem_immutable_id(tmp_ctx, userinfo);
    assert_null(result);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

static void test_decode_onprem_immutable_id_null_value(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* Field present but JSON null (not a string) */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "onPremisesImmutableId", json_null());

    const char *result = decode_onprem_immutable_id(tmp_ctx, userinfo);
    assert_null(result);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

static void test_decode_onprem_immutable_id_wrong_length(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* "AQID" decodes to 3 bytes, not 16 — should return NULL */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "onPremisesImmutableId",
                        json_string("AQID"));

    const char *result = decode_onprem_immutable_id(tmp_ctx, userinfo);
    assert_null(result);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

static void test_decode_onprem_immutable_id_integer_field(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* Field present but is an integer, not a string */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "onPremisesImmutableId", json_integer(42));

    const char *result = decode_onprem_immutable_id(tmp_ctx, userinfo);
    assert_null(result);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

/* -----------------------------------------------------------------------
 * get_user_identifier() integration tests
 *
 * These test the full flow: when user_info_type is NULL (userinfo
 * endpoint response), get_user_identifier() should prefer the decoded
 * onPremisesImmutableId over the Entra "id".
 * ----------------------------------------------------------------------- */

static void test_get_user_identifier_hybrid_user(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "id",
                        json_string(TEST_ENTRA_ID));
    json_object_set_new(userinfo, "onPremisesImmutableId",
                        json_string(TEST_ONPREM_IMMUTABLE_ID));

    /* user_info_type = NULL means userinfo endpoint (not token) */
    const char *result = get_user_identifier(tmp_ctx, userinfo,
                                             NULL, NULL);
    assert_non_null(result);
    /* Should return the AD objectGUID, NOT the Entra id */
    assert_string_equal(result, TEST_AD_OBJECTGUID);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

static void test_get_user_identifier_cloud_only_user(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* Cloud-only user: has "id" but no onPremisesImmutableId */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "id",
                        json_string(TEST_ENTRA_ID));

    const char *result = get_user_identifier(tmp_ctx, userinfo,
                                             NULL, NULL);
    assert_non_null(result);
    /* Should fall back to the Entra id */
    assert_string_equal(result, TEST_ENTRA_ID);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

static void test_get_user_identifier_token_payload(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* When user_info_type is NOT NULL (e.g., "id_token"), the decode
     * should NOT be attempted even if onPremisesImmutableId is present,
     * because token payloads don't come from the Graph API. */
    json_t *payload = json_object();
    assert_non_null(payload);
    json_object_set_new(payload, "sub",
                        json_string("some-sub-claim"));
    json_object_set_new(payload, "onPremisesImmutableId",
                        json_string(TEST_ONPREM_IMMUTABLE_ID));

    const char *result = get_user_identifier(tmp_ctx, payload,
                                             NULL, "id_token");
    assert_non_null(result);
    /* Should return the "sub" claim, NOT the decoded GUID */
    assert_string_equal(result, "some-sub-claim");

    json_decref(payload);
    talloc_free(tmp_ctx);
}

static void test_get_user_identifier_custom_attr(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* When user_identifier_attr is set, it overrides the default
     * "sub"/"id" attribute list. The onPremisesImmutableId decode
     * should still work on the userinfo response. */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "email",
                        json_string("user@example.com"));
    json_object_set_new(userinfo, "onPremisesImmutableId",
                        json_string(TEST_ONPREM_IMMUTABLE_ID));

    const char *result = get_user_identifier(tmp_ctx, userinfo,
                                             "email", NULL);
    assert_non_null(result);
    /* Should still prefer the decoded AD objectGUID */
    assert_string_equal(result, TEST_AD_OBJECTGUID);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

static void test_get_user_identifier_no_id_at_all(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* No "sub", no "id" — should return NULL */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "onPremisesImmutableId",
                        json_string(TEST_ONPREM_IMMUTABLE_ID));

    const char *result = get_user_identifier(tmp_ctx, userinfo,
                                             NULL, NULL);
    assert_null(result);

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

/* -----------------------------------------------------------------------
 * GUID byte-order verification
 *
 * Verify the bytes_le conversion explicitly: first 3 groups are
 * little-endian, last 2 groups are big-endian.
 * ----------------------------------------------------------------------- */

static void test_guid_byte_order(void **state)
{
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);

    /* Manually construct a GUID with a known pattern to verify byte order.
     *
     * Raw bytes: 01 02 03 04  05 06  07 08  09 0a  0b 0c 0d 0e 0f 10
     * Expected GUID (bytes_le):
     *   Group 1 (LE): 04030201
     *   Group 2 (LE): 0605
     *   Group 3 (LE): 0807
     *   Group 4 (BE): 090a
     *   Group 5 (BE): 0b0c0d0e0f10
     */
    /* base64 of bytes 01..10 is "AQIDBAUGBwgJCgsMDQ4PEA==" */
    json_t *userinfo = json_object();
    assert_non_null(userinfo);
    json_object_set_new(userinfo, "onPremisesImmutableId",
                        json_string("AQIDBAUGBwgJCgsMDQ4PEA=="));

    const char *result = decode_onprem_immutable_id(tmp_ctx, userinfo);
    assert_non_null(result);
    assert_string_equal(result, "04030201-0605-0807-090a-0b0c0d0e0f10");

    json_decref(userinfo);
    talloc_free(tmp_ctx);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        /* base64_decode_char() */
        cmocka_unit_test(test_base64_decode_char_uppercase),
        cmocka_unit_test(test_base64_decode_char_lowercase),
        cmocka_unit_test(test_base64_decode_char_digits),
        cmocka_unit_test(test_base64_decode_char_special),
        cmocka_unit_test(test_base64_decode_char_invalid),

        /* base64_decode() */
        cmocka_unit_test(test_base64_decode_known_guid),
        cmocka_unit_test(test_base64_decode_null_input),
        cmocka_unit_test(test_base64_decode_empty_string),
        cmocka_unit_test(test_base64_decode_output_too_small),
        cmocka_unit_test(test_base64_decode_no_padding),
        cmocka_unit_test(test_base64_decode_with_plus_and_slash),

        /* decode_onprem_immutable_id() */
        cmocka_unit_test(test_decode_onprem_immutable_id_success),
        cmocka_unit_test(test_decode_onprem_immutable_id_missing),
        cmocka_unit_test(test_decode_onprem_immutable_id_null_value),
        cmocka_unit_test(test_decode_onprem_immutable_id_wrong_length),
        cmocka_unit_test(test_decode_onprem_immutable_id_integer_field),

        /* get_user_identifier() integration */
        cmocka_unit_test(test_get_user_identifier_hybrid_user),
        cmocka_unit_test(test_get_user_identifier_cloud_only_user),
        cmocka_unit_test(test_get_user_identifier_token_payload),
        cmocka_unit_test(test_get_user_identifier_custom_attr),
        cmocka_unit_test(test_get_user_identifier_no_id_at_all),

        /* GUID byte-order */
        cmocka_unit_test(test_guid_byte_order),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
