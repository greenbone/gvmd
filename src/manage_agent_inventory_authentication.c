/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Configuration and token generation for agent inventory access.
 */

#include "manage_runtime_flags.h"
#if ENABLE_AGENTS
#include "gvmd_config.h"
#include "manage_agent_inventory_authentication.h"

#include <errno.h>
#include <gnutls/crypto.h>
#include <gvm/auth/gvm_auth.h>
#include <string.h>

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Configuration group for agent inventory authentication.
 */
#define AGENT_INVENTORY_AUTH_CONFIG_GROUP "agent_inventory_authentication"

/**
 * @brief Default token lifetime in seconds.
 */
#define DEFAULT_AGENT_JWT_ACCESS_DURATION 600

/**
 * @brief Token lifetime in seconds.
 */
static int agent_jwt_access_duration = DEFAULT_AGENT_JWT_ACCESS_DURATION;

/**
 * @brief Shared secret used to sign agent inventory tokens.
 */
static gvm_jwt_encode_secret_t agent_jwt_encode_secret = NULL;

/**
 * @brief Load the agent inventory token duration and shared secret.
 *
 * @return 0 on success, -1 on invalid or missing configuration.
 */
int
load_agent_inventory_authentication_config (void)
{
  GKeyFile *kf = get_gvmd_config ();
  GError *error = NULL;
  gchar *secret, *duration_str;
  gsize secret_length;
  gvm_jwt_new_secret_err_t secret_err = GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR;

  gvm_jwt_encode_secret_free (agent_jwt_encode_secret);
  agent_jwt_encode_secret = NULL;
  agent_jwt_access_duration = DEFAULT_AGENT_JWT_ACCESS_DURATION;

  duration_str = gvmd_get_env_or_config_string (
    "GVMD_AGENT_JWT_ACCESS_DURATION", kf, AGENT_INVENTORY_AUTH_CONFIG_GROUP,
    "agent_jwt_access_duration");
  if (duration_str)
    {
      gchar *end;
      gint64 duration;

      g_strstrip (duration_str);
      errno = 0;
      duration = g_ascii_strtoll (duration_str, &end, 10);
      if (errno == ERANGE || end == duration_str || *end != '\0'
          || duration <= 0 || duration > G_MAXINT)
        {
          g_warning ("%s: Invalid agent inventory token duration", __func__);
          g_free (duration_str);
          return -1;
        }
      agent_jwt_access_duration = (int) duration;
      g_free (duration_str);
    }
  else if (kf
           && g_key_file_has_key (kf, AGENT_INVENTORY_AUTH_CONFIG_GROUP,
                                  "agent_jwt_access_duration", NULL))
    {
      g_warning ("%s: Invalid agent inventory token duration", __func__);
      return -1;
    }

  secret = gvmd_get_env_or_config_string ("AGENT_CONTROL_USER_TOKEN_SECRET", kf,
                                          AGENT_INVENTORY_AUTH_CONFIG_GROUP,
                                          "agent_jwt_encode_secret");
  if (secret)
    secret_length = strlen (secret);
  else
    {
      gchar *secret_path = gvmd_get_env_or_config_string (
        "GVMD_AGENT_JWT_ENCODE_SECRET_PATH", kf,
        AGENT_INVENTORY_AUTH_CONFIG_GROUP, "agent_jwt_encode_secret_path");
      if (secret_path == NULL)
        {
          g_warning ("%s: No agent inventory token secret configured",
                     __func__);
          return -1;
        }

      if (!g_file_get_contents (secret_path, &secret, &secret_length, &error))
        {
          g_warning ("%s: Could not read agent inventory token secret file: %s",
                     __func__, error->message);
          g_error_free (error);
          g_free (secret_path);
          return -1;
        }
      g_free (secret_path);
    }

  if (secret_length < 32 || memchr (secret, '\0', secret_length))
    {
      g_warning (
        "%s: Agent inventory token secret must contain at least 32 bytes"
        " and no embedded NUL bytes",
        __func__);
      g_free (secret);
      return -1;
    }

  agent_jwt_encode_secret =
    gvm_jwt_new_shared_encode_secret (secret, &secret_err);
  g_free (secret);
  if (agent_jwt_encode_secret == NULL
      || secret_err != GVM_JWT_NEW_SECRET_ERR_OK)
    {
      g_warning ("%s: Could not create agent inventory token secret: %s",
                 __func__, gvm_jwt_new_secret_strerror (secret_err));
      gvm_jwt_encode_secret_free (agent_jwt_encode_secret);
      agent_jwt_encode_secret = NULL;
      return -1;
    }

  return 0;
}

/**
 * @brief Generate an unpadded base64url nonce from 16 random bytes.
 *
 * @return Newly allocated nonce, or NULL on failure. Free with g_free.
 */
static gchar *
generate_nonce (void)
{
  unsigned char nonce_bytes[16];
  gchar *nonce;
  int ret;

  ret = gnutls_rnd (GNUTLS_RND_RANDOM, nonce_bytes, sizeof (nonce_bytes));
  if (ret < 0)
    {
      g_warning ("%s: Could not generate agent inventory token nonce: %s",
                 __func__, gnutls_strerror (ret));
      return NULL;
    }

  nonce = g_base64_encode (nonce_bytes, sizeof (nonce_bytes));
  for (gchar *p = nonce; *p; p++)
    {
      if (*p == '+')
        *p = '-';
      else if (*p == '/')
        *p = '_';
      else if (*p == '=')
        {
          *p = '\0';
          break;
        }
    }

  return nonce;
}

/**
 * @brief Build the agent inventory token payload using a generated nonce.
 *
 * @param[in] nonce  Non-NULL nonce returned by generate_nonce.
 *
 * @return Newly allocated JSON payload. Free with g_free.
 */
static gchar *
generate_payload (const gchar *nonce)
{
  gint64 issued_at = g_get_real_time () / G_USEC_PER_SEC;

  return g_strdup_printf ("{\"v\":1,\"iat\":%" G_GINT64_FORMAT
                          ",\"exp\":%" G_GINT64_FORMAT ",\"nonce\":\"%s\"}",
                          issued_at, issued_at + agent_jwt_access_duration,
                          nonce);
}

/**
 * @brief Generate a signed, two-part agent inventory token.
 *
 * @param[out] token  Newly allocated token on success; otherwise NULL.
 *                   The caller must free it with g_free.
 *
 * @return AGENT_INVENTORY_TOKEN_OK on success,
 *         AGENT_INVENTORY_TOKEN_UNAVAILABLE if agents are disabled or no valid
 *         secret is loaded,
 *         or AGENT_INVENTORY_TOKEN_ERROR on generation failure or NULL output.
 */
int
generate_agent_inventory_token (gchar **token)
{
  gchar *nonce, *payload;
  char *signed_token;
  gvm_jwt_generate_token_err_t token_err =
    GVM_JWT_GENERATE_TOKEN_ERR_INTERNAL_ERROR;

  if (token == NULL)
    return AGENT_INVENTORY_TOKEN_ERROR;
  *token = NULL;

  if (!feature_enabled (FEATURE_ID_AGENTS))
    {
      g_warning ("%s: Agent inventory token generation is unavailable because"
                 " the agents feature is disabled",
                 __func__);
      return AGENT_INVENTORY_TOKEN_UNAVAILABLE;
    }

  if (agent_jwt_encode_secret == NULL)
    return AGENT_INVENTORY_TOKEN_UNAVAILABLE;

  nonce = generate_nonce ();
  if (nonce == NULL)
    return AGENT_INVENTORY_TOKEN_ERROR;

  payload = generate_payload (nonce);
  g_free (nonce);

  signed_token = gvm_jwt_generate_token_with_payload (agent_jwt_encode_secret,
                                                      payload, &token_err);
  g_free (payload);
  if (signed_token == NULL || token_err != GVM_JWT_GENERATE_TOKEN_ERR_OK)
    {
      g_warning ("%s: Could not generate agent inventory token: %s", __func__,
                 gvm_jwt_generate_token_strerror (token_err));
      gvm_auth_str_free (signed_token);
      return AGENT_INVENTORY_TOKEN_ERROR;
    }

  *token = g_strdup (signed_token);
  gvm_auth_str_free (signed_token);
  return AGENT_INVENTORY_TOKEN_OK;
}

#endif /* ENABLE_AGENTS */
