/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file manage_tls_certificates.c
 * @brief GVM management layer: TLS Certificates
 *
 * The TLS Certificates helper functions for the GVM management layer.
 */

/**
 * @brief Enable extra functions.
 *
 * time.h in glibc2 needs this for strptime.
 */
#define _XOPEN_SOURCE

#include "manage_tls_certificates.h"

#include <string.h>

/**
 * @brief Extract data from a SSLDetails:[...] host detail value
 *
 * This will try to free existing strings at the output pointers with g_free,
 *  so the caller must ensure it is safe to do so.
 *
 * @param[in]  ssldetails       The host detail value.
 * @param[out] activation_time  Pointer to return the activation time.
 * @param[out] expiration_time  Pointer to return the expiration time.
 * @param[out] issuer           Pointer to return the issuer.
 * @param[out] serial           Pointer to return the serial.
 */
void
parse_ssldetails (const char *ssldetails,
                  time_t *activation_time,
                  time_t *expiration_time,
                  gchar **issuer,
                  gchar **serial)
{
  gchar **ssldetails_split, **ssldetails_point;

  if (ssldetails == NULL)
    {
      g_warning ("%s: ssldetails is NULL", __func__);
      return;
    }

  ssldetails_split = g_strsplit (ssldetails, "|", -1);
  ssldetails_point = ssldetails_split;
  while (*ssldetails_point)
    {
      gchar **detail_split;
      detail_split = g_strsplit (*ssldetails_point, ":", 2);

      if (detail_split[0] && detail_split[1])
        {
          if (strcmp (detail_split[0], "notBefore") == 0)
            {
              if (strcmp (detail_split[1], ""))
                {
                  // Time is given as UTC time and uses special format
                  struct tm tm;
                  memset (&tm, 0, sizeof (struct tm));
                  tm.tm_isdst = -1;

                  if (strptime (detail_split[1], "%Y%m%dT%H%M%S", &tm)[0] == 0)
                    *activation_time = mktime (&tm);
                  else
                    *activation_time = -1;
                }
              else
                *activation_time = 0;
            }
          else if (strcmp (detail_split[0], "notAfter") == 0)
            {
              if (strcmp (detail_split[1], ""))
                {
                  // Time is given as UTC time and uses special format
                  struct tm tm;
                  memset (&tm, 0, sizeof (struct tm));
                  tm.tm_isdst = -1;

                  if (strptime (detail_split[1], "%Y%m%dT%H%M%S", &tm)[0] == 0)
                    *expiration_time = mktime (&tm);
                  else
                    *expiration_time = -1;
                }
              else
                *expiration_time = 0;
            }
          else if (strcmp (detail_split[0], "issuer") == 0
                   && strcmp (detail_split[1], ""))
            {
              g_free (*issuer);
              *issuer = g_strdup (detail_split[1]);
            }
          else if (strcmp (detail_split[0], "serial") == 0
                    && strcmp (detail_split[1], ""))
            {
              g_free (*serial);
              *serial = g_strdup (detail_split[1]);
            }
        }
      g_strfreev (detail_split);
      ssldetails_point ++;
    }
  g_strfreev (ssldetails_split);
}

/**
 * @brief Get a string representation of a certificate format.
 *
 * @param[in]  certificate_format  The format as gnutls_x509_crt_fmt_t.
 *
 * @return A string representation of the format (e.g. "PEM" or "DER").
 */
const char*
tls_certificate_format_str (gnutls_x509_crt_fmt_t certificate_format)
{
  switch (certificate_format)
    {
      case GNUTLS_X509_FMT_DER:
        return "DER";
      case GNUTLS_X509_FMT_PEM:
        return "PEM";
      default:
        return "unknown";
    }
}
