/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Implementation of HTTP scanner management functions for GVMD.
 *
 * This file provides the implementation for connecting to an HTTP-based
 * scanner and managing connector properties.
 */
#if ENABLE_HTTP_SCANNER
#include "manage_http_scanner.h"
#include "manage_sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Create a new connection to a HTTP scanner.
 *
 * @param[in]   scanner     Scanner.
 * @param[in]   scan_id     scan uuid for creating http scan.
 *
 * @return New connection if success, NULL otherwise.
 */
http_scanner_connector_t
http_scanner_connect (scanner_t scanner, const char *scan_id)
{
  gboolean has_relay;
  int port;
  http_scanner_connector_t connection;
  char *host, *ca_pub, *key_pub, *key_priv;
  const char *protocol;

  assert (scanner);
  has_relay = scanner_has_relay (scanner);
  host = scanner_host (scanner, has_relay);
  port = scanner_port (scanner, has_relay);
  ca_pub = scanner_ca_pub (scanner);
  key_pub = scanner_key_pub (scanner);
  key_priv = scanner_key_priv (scanner);

  /* Determine protocol based on certificate presence */
  if (ca_pub && key_pub && key_priv)
    protocol = "https";
  else
    protocol = "http";

  connection = http_scanner_connector_new ();

  http_scanner_connector_builder (connection, HTTP_SCANNER_HOST, host);
  http_scanner_connector_builder (connection, HTTP_SCANNER_CA_CERT, ca_pub);
  http_scanner_connector_builder (connection, HTTP_SCANNER_KEY, key_priv);
  http_scanner_connector_builder (connection, HTTP_SCANNER_CERT, key_pub);
  http_scanner_connector_builder (connection, HTTP_SCANNER_PROTOCOL, protocol);
  http_scanner_connector_builder (connection, HTTP_SCANNER_PORT,
                                  (void *) &port);

  if (scan_id && scan_id[0] != '\0')
    http_scanner_connector_builder (connection, HTTP_SCANNER_SCAN_ID, scan_id);

  g_free (host);
  g_free (ca_pub);
  g_free (key_pub);
  g_free (key_priv);

  return connection;
}

#endif
