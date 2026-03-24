/* Copyright (C) 2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: authentication.
 *
 * General authentication functions.
 */

#include "gvmd_config.h"
#include "manage_authentication.h"
#include "manage_runtime_flags.h"
#include <gvm/util/passwordbasedauthentication.h>

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief PBA settings.
 *
 * Prefer stack rather than heap so that we use the defaults on usage failure
 * rather than having to check and fail.
 */
struct PBASettings settings = {{0}, COUNT_DEFAULT, PREFIX_DEFAULT};

/**
 * @brief Set the pepper, count and prefix used by authentication.
 *
 * When pepper is a NULL pointer, prefix is a NULL pointer or count is 0 then
 * the previous setting of that setting will be kept.
 *
 * This is mainly to allow easier configuration within gvmd.c so that it can
 * used parameterized without repeating the same information there.
 *
 * The initial defaults are set to no-pepper, COUNT_DEFAULT and PREFIX_DEFAULT
 * of gvm-libs.
 *
 * @param[in] pepper  A static hidden addition to the randomly generated salt
 * @param[in] pepper_size  The size of pepper; it must not be larger than
 *                         MAX_PEPPER_SIZE
 * @param[in] count   The amount of rounds used to calculate the hash; if 0 then
 *                    COUNT_DEFAULT will be used
 * @param[in] prefix  the used algorithm, if NULL pointer then the most secure
 *                    available algorithm will be used.
 *
 * @return GMA_SUCCESS when the settings are set or GMA_ERR if there was a
 * failure.
 */
enum manage_authentication_rc
manage_authentication_setup (const char *pepper, unsigned int pepper_size,
                             unsigned int count, char *prefix)
{
  struct PBASettings *tmp = pba_init (pepper, pepper_size, count, prefix);
  enum manage_authentication_rc rc = GMA_ERR;
  unsigned int i;

  if (tmp == NULL)
    goto exit;
  // only override pepper when pepper is initially set otherwise keep
  // previous pepper
  for (i = 0; pepper != NULL && i < MAX_PEPPER_SIZE; i++)
    settings.pepper[i] = tmp->pepper[i];
  settings.count = count > 0 ? tmp->count : settings.count;
  settings.prefix = prefix != NULL ? tmp->prefix : settings.prefix;
  pba_finalize (tmp);
  rc = GMA_SUCCESS;

exit:
  return rc;
}

/**
 * @brief Create a hash based on the settings from manage_authentication_setup.
 *
 * @param[in] password  The password to be hashed.
 *
 * @return The hash, or a NULL pointer on failure. Caller must free.
 */
char *
manage_authentication_hash (const char *password)
{
  return pba_hash (&settings, password);
}

/**
 * @brief Verify a password with a hash.
 *
 * @param[in] password  The clear text password to be verified.
 * @param[in] hash      The stored hash to verify the password against.
 *
 * @return GMA_SUCCESS when password is valid,
 *         GMA_HASH_VALID_BUT_DATED when password is valid but a new hash
 *                                  should be created and stored.
 *         GMA_HASH_INVALID when password is invalid
 *         GMA_ERR when an unexpected error occurs.
 */
enum manage_authentication_rc
manage_authentication_verify (const char *hash, const char *password)
{
  enum pba_rc pba_rc = pba_verify_hash (&settings, hash, password);
  enum manage_authentication_rc rc;
  switch (pba_rc)
    {
    case VALID:
      rc = GMA_SUCCESS;
      break;
    case INVALID:
      rc = GMA_HASH_INVALID;
      break;
    case UPDATE_RECOMMENDED:
      rc = GMA_HASH_VALID_BUT_DATED;
      break;
    default:
      rc = GMA_ERR;
      break;
    }

  return rc;
}

#if ENABLE_JWT_AUTH

/**
 * @brief Default lifetime for access tokens in seconds
 */
#define DEFAULT_ACCESS_TOKEN_LIFETIME 60

/**
 * @brief Lifetime for access tokens in seconds
 */
int
access_token_lifetime = DEFAULT_ACCESS_TOKEN_LIFETIME;

/**
 * @brief The type of secret used for JSON web tokens (JWTs).
 */
gvm_jwt_secret_type_t jwt_secret_type = 0;

/**
 * @brief Secret for decoding JSON web tokens (JWTs).
 */
static gvm_jwt_decode_secret_t jwt_decode_secret = NULL;

/**
 * @brief Secret for encoding JSON web tokens (JWTs).
 */
static gvm_jwt_encode_secret_t jwt_encode_secret = NULL;


/**
 * @brief Group name for authentication settings in the config file
 */
#define AUTH_CONFIG_GROUP "authentication"

/**
 * @brief Create the JWT decode secret from data or a file.
 *
 * @param[in]  secret_type    The expected JWT secret type.
 * @param[in]  secret_str     The secret data, will override file.
 * @param[in]  secret_path    Path to the secret file if secret_str is not set.
 * @param[out] decode_secret  Output of the decode secret.
 *
 * @return 0 success, -1 error
 */
static int
load_jwt_decode_secret (gvm_jwt_secret_type_t secret_type,
                        const char *secret_str,
                        const char *secret_path,
                        gvm_jwt_decode_secret_t *decode_secret)
{
  gvm_jwt_new_secret_err_t secret_err = GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR;
  *decode_secret = NULL;

  if (secret_str)
    {
      g_debug ("%s: Using secret given directly", __func__);
      *decode_secret = gvm_jwt_new_decode_secret (secret_type, secret_str,
                                                  &secret_err);
    }
  else
    {
      GError *error = NULL;
      gchar *secret_from_file = NULL;
      if (! g_file_get_contents (secret_path, &secret_from_file, NULL, &error))
        {
          g_warning ("Could not read JWT decode secret file: %s",
                     error->message);
          g_error_free (error);
          return -1;
        }
      g_debug ("%s: Using secret from file '%s'", __func__, secret_path);
      *decode_secret = gvm_jwt_new_decode_secret (secret_type,
                                                  secret_from_file,
                                                  &secret_err);
      g_free (secret_from_file);
    }

  if (*decode_secret == NULL || secret_err != GVM_JWT_NEW_SECRET_ERR_OK)
    {
      g_warning ("Could not parse JWT decode secret: %s",
                 gvm_jwt_new_secret_strerror (secret_err));
      return -1;
    }

  return 0;
}

/**
 * @brief Create the JWT encode secret from data or a file.
 *
 * @param[in]  secret_type    The expected JWT secret type.
 * @param[in]  secret_str     The secret data, will override file.
 * @param[in]  secret_path    Path to the secret file if secret_str is not set.
 * @param[out] decode_secret  Output of the decode secret.
 *
 * @return 0 success, -1 error
 */
static int
load_jwt_encode_secret (gvm_jwt_secret_type_t secret_type,
                        const char *secret_str,
                        const char *secret_path,
                        gvm_jwt_encode_secret_t *encode_secret)
{
  gvm_jwt_new_secret_err_t secret_err = GVM_JWT_NEW_SECRET_ERR_INTERNAL_ERROR;
  *encode_secret = NULL;

  if (secret_str)
    {
      g_debug ("%s: Using secret given directly", __func__);
      *encode_secret = gvm_jwt_new_encode_secret (secret_type, secret_str,
                                                  &secret_err);
    }
  else if (secret_path)
    {
      GError *error = NULL;
      gchar *secret_from_file = NULL;
      if (! g_file_get_contents (secret_path, &secret_from_file, NULL, &error))
        {
          g_warning ("Could not read JWT encode secret file: %s",
                     error->message);
          g_error_free (error);
          return -1;
        }
      g_debug ("%s: Using secret from file '%s'", __func__, secret_path);
      *encode_secret = gvm_jwt_new_encode_secret (secret_type,
                                                  secret_from_file,
                                                  &secret_err);
      g_free (secret_from_file);
    }

  if (*encode_secret == NULL || secret_err != GVM_JWT_NEW_SECRET_ERR_OK)
    {
      g_warning ("Could not parse JWT encode secret: %s",
                 gvm_jwt_new_secret_strerror (secret_err));
      return -1;
    }

  return 0;
}

/**
 * @brief Load the JWT secrets according to the gvmd config file.
 *
 * @param[in]  kf  GKeyFile to get config values from.
 *
 * @return 0 success, -1 error
 */
static int
load_jwt_secrets (GKeyFile *kf)
{
  gchar *secret_str = NULL, *secret_path = NULL;
  gchar *secret_type_str;
  gvm_jwt_secret_type_t new_secret_type;
  gvm_jwt_decode_secret_t new_decode_secret = NULL;
  gvm_jwt_encode_secret_t new_encode_secret = NULL;
  int ret;

  // Free old secrets
  jwt_secret_type = 0;
  if (jwt_decode_secret)
    {
      gvm_jwt_decode_secret_free (jwt_decode_secret);
      jwt_decode_secret = NULL;
    }
  if (jwt_encode_secret)
    {
      gvm_jwt_encode_secret_free (jwt_encode_secret);
      jwt_encode_secret = NULL;
    }

  // Set new secret type
  secret_type_str
    = gvmd_get_env_or_config_string ("GVMD_JWT_SECRET_TYPE",
                                     kf,
                                     AUTH_CONFIG_GROUP,
                                     "jwt_secret_type");

  if (secret_type_str == NULL || strcmp (secret_type_str, "") == 0)
    {
      g_debug ("No JWT secret type set");
      return 0;
    }

  if (strcasecmp (secret_type_str, "shared") == 0)
    new_secret_type = GVM_JWT_SECRET_TYPE_SHARED;
  else if (strcasecmp (secret_type_str, "ECDSA") == 0
           || strcasecmp (secret_type_str, "ECDSA PEM") == 0)
    new_secret_type = GVM_JWT_SECRET_TYPE_EC_PEM;
  else if (strcasecmp (secret_type_str, "RSA") == 0
           || strcasecmp (secret_type_str, "RSA PEM") == 0)
    new_secret_type = GVM_JWT_SECRET_TYPE_RSA_PEM;
  else
    {
      g_warning ("Unknown JWT secret type '%s'", secret_type_str);
      g_free (secret_type_str);
      return -1;
    }

  g_free (secret_type_str);


  // Get decode secret
  ret = 0;
  secret_str
    = gvmd_get_env_or_config_string ("GVMD_JWT_DECODE_SECRET",
                                     kf,
                                     AUTH_CONFIG_GROUP,
                                     "jwt_decode_secret");
  secret_path
    = gvmd_get_env_or_config_string ("GVMD_JWT_DECODE_SECRET_PATH",
                                     kf,
                                     AUTH_CONFIG_GROUP,
                                     "jwt_decode_secret_path");
  if (secret_str || secret_path)
    ret = load_jwt_decode_secret (new_secret_type, secret_str, secret_path,
                                  &new_decode_secret);
  else
    g_debug ("No JWT decode secret set");

  g_free (secret_str);
  g_free (secret_path);

  if (ret)
    return -1;

  // Get encode secret
  ret = 0;
  secret_str
    = gvmd_get_env_or_config_string ("GVMD_JWT_ENCODE_SECRET",
                                     kf,
                                     AUTH_CONFIG_GROUP,
                                     "jwt_encode_secret");
  secret_path
    = gvmd_get_env_or_config_string ("GVMD_JWT_ENCODE_SECRET_PATH",
                                     kf,
                                     AUTH_CONFIG_GROUP,
                                     "jwt_encode_secret_path");
  if (secret_str || secret_path)
    ret = load_jwt_encode_secret (new_secret_type, secret_str, secret_path,
                                  &new_encode_secret);
  else
    g_debug ("No JWT encode secret set");
  g_free (secret_str);
  g_free (secret_path);

  if (ret)
    {
      gvm_jwt_decode_secret_free (new_decode_secret);
      return -1;
    }

  jwt_secret_type = new_secret_type;
  jwt_decode_secret = new_decode_secret;
  jwt_encode_secret = new_encode_secret;

  return 0;
}

/**
 * @brief Load the authentication configuration options and files.
 *
 * @return 0 success, -1 error
 */
int
load_authentication_config ()
{
  int has_value, value;
  GKeyFile *kf = get_gvmd_config ();

  access_token_lifetime = DEFAULT_ACCESS_TOKEN_LIFETIME;
  gvmd_config_get_int (kf, AUTH_CONFIG_GROUP, "access_token_lifetime",
                    &has_value, &value);
  gvmd_config_resolve_int ("GVMD_ACCESS_TOKEN_LIFETIME", has_value, value,
                            &access_token_lifetime);

  return load_jwt_secrets (kf);
}

/**
 * @brief Get the access token lifetime in seconds
 *
 * @return The access token lifetime in seconds
 */
int
get_access_token_lifetime ()
{
  return access_token_lifetime;
}

/**
 * @brief Gets the JWT decode secret.
 *
 * @return The JWT decode secret.
 */
gvm_jwt_decode_secret_t
get_jwt_decode_secret ()
{
  return jwt_decode_secret;
}

/**
 * @brief Gets the JWT encode secret.
 *
 * @return The JWT encode secret.
 */
gvm_jwt_encode_secret_t
get_jwt_encode_secret ()
{
  return jwt_encode_secret;
}

#endif /* ENABLE_JWT_AUTH */
