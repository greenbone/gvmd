/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_credential_store_cyberark.h
 * @brief GVM manage layer: CyberArk credential store.
 *
 * Management headers of the CyberArk credential store.
 */

#ifndef _GVMD_MANAGE_CREDENTIAL_STORE_CYBERARK_H
#define _GVMD_MANAGE_CREDENTIAL_STORE_CYBERARK_H

#include "manage_credential_stores.h"

verify_credential_store_return_t
verify_cyberark_credential_store (const char *host,
                                  const char *path,
                                  GHashTable *preferences,
                                  gchar **message);
int
cyberark_login_password_credential_data (const char *,
                                         const char *,
                                         const char *,
                                         gchar **,
                                         gchar **);


#endif /* _GVMD_MANAGE_CREDENTIAL_STORE_CYBERARK_H */