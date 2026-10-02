/* Copyright (C) 2009-2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_SQL_CREDENTIALS_H
#define _GVMD_MANAGE_SQL_CREDENTIALS_H

#include "manage_credentials.h"

void
update_credential_modification_time (credential_t);

int
set_credential_name (credential_t,
                     const char *);

int
set_credential_comment (credential_t,
                        const char *);
int
set_credential_allow_insecure (credential_t,
                               int);

credential_return_t
insert_credential_base (const credential_data_t *,
                        const gchar *,
                        credential_t *);

int
set_credential_data (credential_t,
                     const char*,
                     const char*);

int
copy_credential_rows (const char*,
                      const char*,
                      const char *,
                      credential_t*);

#endif /* _GVMD_MANAGE_SQL_CREDENTIALS_H */
