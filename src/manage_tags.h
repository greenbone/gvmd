/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_TAGS_H
#define _GVMD_MANAGE_TAGS_H

#include "manage_resources.h"

char*
tag_uuid (tag_t);

int
copy_tag (const char *, const char *, const char *, tag_t *);

int
delete_tag (const char *, int);

int
create_tag (const char *, const char *, const char *, const char *,
            array_t *, const char *, const char *, tag_t *, gchar **);

int
modify_tag (const char *, const char *, const char *, const char *,
            const char *, array_t *, const char *, const char *, const char*,
            gchar **);

#endif /* not _GVMD_MANAGE_TAGS_H */
