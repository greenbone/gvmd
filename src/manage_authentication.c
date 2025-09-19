/* Copyright (C) 2022 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "manage_authentication.h"
#include <gvm/util/passwordbasedauthentication.h>

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

// prefer stack rather than heap so that we use the defaults on usage failure
// rather than having to check and fail.
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
