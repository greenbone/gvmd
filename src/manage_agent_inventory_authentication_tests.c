/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cgreen/cgreen.h>
#include <cjson/cJSON.h>
#include <glib/gstdio.h>
#include <gnutls/crypto.h>

static int
test_gnutls_rnd (gnutls_rnd_level_t, void *, size_t);

/*
 * Mock gnutls_rnd to simulate random-source failures in tests.
 */
#define gnutls_rnd test_gnutls_rnd
#include "manage_agent_inventory_authentication.c"
#undef gnutls_rnd

Describe (manage_agent_inventory_authentication);

static gchar *test_directory, *config_path, *secret_path;
static gboolean random_failure;

#define TEST_SECRET "0123456789abcdef0123456789abcdef"
#define TEST_CONFIG_SECRET "agent_jwt_encode_secret = " TEST_SECRET "\n"

static int
test_gnutls_rnd (gnutls_rnd_level_t level, void *data, size_t length)
{
  if (random_failure)
    return GNUTLS_E_RANDOM_FAILED;
  return gnutls_rnd (level, data, length);
}

BeforeEach (manage_agent_inventory_authentication)
{
  unsetenv ("AGENT_CONTROL_USER_TOKEN_SECRET");
  unsetenv ("GVMD_AGENT_JWT_ACCESS_DURATION");
  unsetenv ("GVMD_AGENT_JWT_ENCODE_SECRET_PATH");
  g_setenv ("GVMD_ENABLE_AGENTS", "1", TRUE);
  assert_that (runtime_flags_init (), is_equal_to (0));
  random_failure = FALSE;
  test_directory = g_dir_make_tmp ("gvmd-agent-inventory-XXXXXX", NULL);
  assert_that (test_directory, is_not_null);
  config_path = g_build_filename (test_directory, "gvmd.conf", NULL);
  secret_path = g_build_filename (test_directory, "secret", NULL);
}

AfterEach (manage_agent_inventory_authentication)
{
  gvm_jwt_encode_secret_free (agent_jwt_encode_secret);
  agent_jwt_encode_secret = NULL;
  unsetenv ("AGENT_CONTROL_USER_TOKEN_SECRET");
  unsetenv ("GVMD_AGENT_JWT_ACCESS_DURATION");
  unsetenv ("GVMD_AGENT_JWT_ENCODE_SECRET_PATH");
  unsetenv ("GVMD_ENABLE_AGENTS");
  g_remove (config_path);
  g_remove (secret_path);
  g_rmdir (test_directory);
  g_free (config_path);
  g_free (secret_path);
  g_free (test_directory);
}

static void
set_test_config (const gchar *settings)
{
  gchar *config =
    g_strdup_printf ("[agent_inventory_authentication]\n%s", settings);
  assert_that (g_file_set_contents (config_path, config, -1, NULL),
               is_equal_to (TRUE));
  assert_that (load_gvmd_config (config_path), is_equal_to (0));
  g_free (config);
}

static guchar *
decode_base64url (const gchar *encoded, gsize *length)
{
  gchar *padded = g_strdup_printf (
    "%s%.*s", encoded, (int) ((4 - strlen (encoded) % 4) % 4), "===");
  guchar *decoded;

  for (gchar *p = padded; *p; p++)
    {
      if (*p == '-')
        *p = '+';
      else if (*p == '_')
        *p = '/';
    }
  decoded = g_base64_decode (padded, length);
  g_free (padded);
  return decoded;
}

/**
 * @brief Check token claims and independently verify HMAC using GLib.
 */
static void
assert_valid_token (const gchar *token, const gchar *secret, int duration)
{
  gchar **parts = g_strsplit (token, ".", -1);
  gsize payload_length, signature_length, nonce_length;
  guchar *payload, *signature, *nonce;
  gchar *json;
  cJSON *claims, *issued_at, *expires_at, *nonce_claim;
  GHmac *hmac;
  guchar expected[32];
  gsize expected_length = sizeof (expected);
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;

  assert_that (g_strv_length (parts), is_equal_to (2));
  assert_that (strchr (token, '='), is_null);
  payload = decode_base64url (parts[0], &payload_length);
  json = g_strndup ((const gchar *) payload, payload_length);
  claims = cJSON_Parse (json);
  assert_that (claims, is_not_null);
  assert_that (cJSON_GetNumberValue (cJSON_GetObjectItem (claims, "v")),
               is_equal_to (1));
  issued_at = cJSON_GetObjectItem (claims, "iat");
  expires_at = cJSON_GetObjectItem (claims, "exp");
  assert_that (cJSON_IsNumber (issued_at), is_equal_to (TRUE));
  assert_that (cJSON_IsNumber (expires_at), is_equal_to (TRUE));
  assert_that ((gint64) issued_at->valuedouble, is_greater_than (now - 10));
  assert_that ((gint64) issued_at->valuedouble, is_less_than (now + 1));
  assert_that ((gint64) (expires_at->valuedouble - issued_at->valuedouble),
               is_equal_to (duration));
  nonce_claim = cJSON_GetObjectItem (claims, "nonce");
  assert_that (cJSON_IsString (nonce_claim), is_equal_to (TRUE));
  assert_that (strlen (nonce_claim->valuestring), is_equal_to (22));
  nonce = decode_base64url (nonce_claim->valuestring, &nonce_length);
  assert_that (nonce_length, is_equal_to (16));

  signature = decode_base64url (parts[1], &signature_length);
  assert_that (signature_length, is_equal_to (sizeof (expected)));
  hmac =
    g_hmac_new (G_CHECKSUM_SHA256, (const guchar *) secret, strlen (secret));
  g_hmac_update (hmac, (const guchar *) parts[0], strlen (parts[0]));
  g_hmac_get_digest (hmac, expected, &expected_length);
  assert_that (memcmp (signature, expected, sizeof (expected)),
               is_equal_to (0));

  g_hmac_unref (hmac);
  g_free (signature);
  g_free (nonce);
  cJSON_Delete (claims);
  g_free (json);
  g_free (payload);
  g_strfreev (parts);
}

Ensure (manage_agent_inventory_authentication,
        unavailable_without_configuration)
{
  gchar *token = (gchar *) "unchanged";

  set_test_config ("");
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (-1));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_UNAVAILABLE));
  assert_that (token, is_null);
}

Ensure (manage_agent_inventory_authentication,
        generates_token_with_default_duration)
{
  gchar *token = NULL;

  set_test_config (TEST_CONFIG_SECRET);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_valid_token (token, TEST_SECRET, 600);
  g_free (token);
}

Ensure (manage_agent_inventory_authentication, unavailable_when_agents_disabled)
{
  gchar *token = (gchar *) "unchanged";

  set_test_config (TEST_CONFIG_SECRET);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  g_setenv ("GVMD_ENABLE_AGENTS", "0", TRUE);
  assert_that (runtime_flags_init (), is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));

  /* Disabled generation must return before accessing the random source. */
  random_failure = TRUE;
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_UNAVAILABLE));
  assert_that (token, is_null);
  assert_that (generate_agent_inventory_token (NULL),
               is_equal_to (AGENT_INVENTORY_TOKEN_ERROR));
}

Ensure (manage_agent_inventory_authentication, uses_duration_and_unique_nonce)
{
  gchar *first = NULL, *second = NULL;

  set_test_config (TEST_CONFIG_SECRET "agent_jwt_access_duration = 1200\n");
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  assert_that (generate_agent_inventory_token (&first),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_that (generate_agent_inventory_token (&second),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_valid_token (first, TEST_SECRET, 1200);
  assert_valid_token (second, TEST_SECRET, 1200);
  assert_that (first, is_not_equal_to_string (second));
  g_free (first);
  g_free (second);
}

Ensure (manage_agent_inventory_authentication,
        environment_overrides_configuration)
{
  gchar *token = NULL;

  set_test_config (
    "agent_jwt_encode_secret = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    "agent_jwt_encode_secret_path = /nonexistent/secret\n");
  g_setenv ("AGENT_CONTROL_USER_TOKEN_SECRET", TEST_SECRET, TRUE);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_valid_token (token, TEST_SECRET, 600);
  g_free (token);
}

Ensure (manage_agent_inventory_authentication, configured_secret_overrides_file)
{
  gchar *token = NULL;

  set_test_config (TEST_CONFIG_SECRET
                   "agent_jwt_encode_secret_path = /nonexistent/secret\n");
  g_setenv ("GVMD_AGENT_JWT_ENCODE_SECRET_PATH", "/nonexistent/env-secret",
            TRUE);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_valid_token (token, TEST_SECRET, 600);
  g_free (token);
}

Ensure (manage_agent_inventory_authentication, preserves_secret_file_bytes)
{
  gchar *token = NULL;
  gchar *settings =
    g_strdup_printf ("agent_jwt_encode_secret_path = %s\n", secret_path);

  assert_that (g_file_set_contents (secret_path, TEST_SECRET "\n", -1, NULL),
               is_equal_to (TRUE));
  set_test_config (settings);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_valid_token (token, TEST_SECRET "\n", 600);
  g_free (token);
  g_free (settings);
}

Ensure (manage_agent_inventory_authentication,
        environment_duration_overrides_configuration)
{
  gchar *token = NULL;

  set_test_config (TEST_CONFIG_SECRET "agent_jwt_access_duration = invalid\n");
  g_setenv ("GVMD_AGENT_JWT_ACCESS_DURATION", "900", TRUE);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_valid_token (token, TEST_SECRET, 900);
  g_free (token);
}

Ensure (manage_agent_inventory_authentication,
        environment_secret_path_overrides_configuration)
{
  gchar *token = NULL;

  assert_that (g_file_set_contents (secret_path, TEST_SECRET, -1, NULL),
               is_equal_to (TRUE));
  set_test_config ("agent_jwt_encode_secret_path = /nonexistent/secret\n");
  g_setenv ("GVMD_AGENT_JWT_ENCODE_SECRET_PATH", secret_path, TRUE);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_OK));
  assert_valid_token (token, TEST_SECRET, 600);
  g_free (token);
}

Ensure (manage_agent_inventory_authentication,
        rejects_invalid_environment_duration)
{
  const gchar *durations[] = {
    "", "0", "-1", "invalid", "2147483648", "999999999999999999999999", "600s",
  };

  set_test_config (TEST_CONFIG_SECRET "agent_jwt_access_duration = 1200\n");
  for (gsize i = 0; i < G_N_ELEMENTS (durations); i++)
    {
      gchar *token = NULL;

      g_unsetenv ("GVMD_AGENT_JWT_ACCESS_DURATION");
      assert_that (load_agent_inventory_authentication_config (),
                   is_equal_to (0));
      g_setenv ("GVMD_AGENT_JWT_ACCESS_DURATION", durations[i], TRUE);
      assert_that (load_agent_inventory_authentication_config (),
                   is_equal_to (-1));
      assert_that (generate_agent_inventory_token (&token),
                   is_equal_to (AGENT_INVENTORY_TOKEN_UNAVAILABLE));
      assert_that (token, is_null);
    }
}

Ensure (manage_agent_inventory_authentication,
        rejects_unreadable_environment_secret_path)
{
  gchar *token = NULL;
  gchar *settings =
    g_strdup_printf ("agent_jwt_encode_secret_path = %s\n", secret_path);

  assert_that (g_file_set_contents (secret_path, TEST_SECRET, -1, NULL),
               is_equal_to (TRUE));
  set_test_config (settings);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  g_setenv ("GVMD_AGENT_JWT_ENCODE_SECRET_PATH", "/nonexistent/env-secret",
            TRUE);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (-1));
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_UNAVAILABLE));
  assert_that (token, is_null);
  g_free (settings);
}

Ensure (manage_agent_inventory_authentication,
        rejects_invalid_duration_and_clears_secret)
{
  const gchar *durations[] = {"0", "-1", "invalid", "2147483648"};

  for (gsize i = 0; i < G_N_ELEMENTS (durations); i++)
    {
      gchar *token = NULL;
      gchar *settings = g_strdup_printf (
        TEST_CONFIG_SECRET "agent_jwt_access_duration = %s\n", durations[i]);

      set_test_config (TEST_CONFIG_SECRET);
      assert_that (load_agent_inventory_authentication_config (),
                   is_equal_to (0));
      set_test_config (settings);
      assert_that (load_agent_inventory_authentication_config (),
                   is_equal_to (-1));
      assert_that (generate_agent_inventory_token (&token),
                   is_equal_to (AGENT_INVENTORY_TOKEN_UNAVAILABLE));
      assert_that (token, is_null);
      g_free (settings);
    }
}

Ensure (manage_agent_inventory_authentication,
        rejects_short_or_unreadable_secret)
{
  const gchar *settings[] = {
    "agent_jwt_encode_secret = 0123456789abcdef0123456789abcde\n",
    "agent_jwt_encode_secret_path = /nonexistent/secret\n",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (settings); i++)
    {
      gchar *token = NULL;

      set_test_config (settings[i]);
      assert_that (load_agent_inventory_authentication_config (),
                   is_equal_to (-1));
      assert_that (generate_agent_inventory_token (&token),
                   is_equal_to (AGENT_INVENTORY_TOKEN_UNAVAILABLE));
      assert_that (token, is_null);
    }

  set_test_config (TEST_CONFIG_SECRET);
  g_setenv ("AGENT_CONTROL_USER_TOKEN_SECRET", "", TRUE);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (-1));
}

Ensure (manage_agent_inventory_authentication,
        rejects_embedded_nul_in_secret_file)
{
  const gchar data[] = TEST_SECRET "\0ignored";
  gchar *settings =
    g_strdup_printf ("agent_jwt_encode_secret_path = %s\n", secret_path);

  assert_that (g_file_set_contents (secret_path, data, sizeof (data) - 1, NULL),
               is_equal_to (TRUE));
  set_test_config (settings);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (-1));
  g_free (settings);
}

Ensure (manage_agent_inventory_authentication, reports_generation_failure)
{
  gchar *token = (gchar *) "unchanged";

  set_test_config (TEST_CONFIG_SECRET);
  assert_that (load_agent_inventory_authentication_config (), is_equal_to (0));
  random_failure = TRUE;
  assert_that (generate_agent_inventory_token (&token),
               is_equal_to (AGENT_INVENTORY_TOKEN_ERROR));
  assert_that (token, is_null);
  assert_that (generate_agent_inventory_token (NULL),
               is_equal_to (AGENT_INVENTORY_TOKEN_ERROR));
}

int
main (void)
{
  TestSuite *suite = create_test_suite ();
  TestReporter *reporter = create_text_reporter ();
  int ret;

  add_test_with_context (suite, manage_agent_inventory_authentication,
                         unavailable_without_configuration);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         generates_token_with_default_duration);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         unavailable_when_agents_disabled);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         uses_duration_and_unique_nonce);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         environment_overrides_configuration);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         configured_secret_overrides_file);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         preserves_secret_file_bytes);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         environment_duration_overrides_configuration);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         environment_secret_path_overrides_configuration);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         rejects_invalid_environment_duration);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         rejects_unreadable_environment_secret_path);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         rejects_invalid_duration_and_clears_secret);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         rejects_short_or_unreadable_secret);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         rejects_embedded_nul_in_secret_file);
  add_test_with_context (suite, manage_agent_inventory_authentication,
                         reports_generation_failure);

  ret = run_test_suite (suite, reporter);
  destroy_reporter (reporter);
  destroy_test_suite (suite);
  return ret;
}
