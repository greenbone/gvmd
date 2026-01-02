/* Copyright (C) 2019-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: TLS Certificates headers
 *
 * Headers for TLS Certificates SQL for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_TLS_CERTIFICATES_H
#define _GVMD_MANAGE_TLS_CERTIFICATES_H

#include "manage.h"
#include "iterator.h"

int
tls_certificate_count (const get_data_t *);

int
init_tls_certificate_iterator (iterator_t *, get_data_t *);

const char*
tls_certificate_iterator_certificate (iterator_t*);

const char*
tls_certificate_iterator_subject_dn (iterator_t*);

const char*
tls_certificate_iterator_issuer_dn (iterator_t*);

int
tls_certificate_iterator_trust (iterator_t *);

const char*
tls_certificate_iterator_md5_fingerprint (iterator_t*);

const char*
tls_certificate_iterator_activation_time (iterator_t*);

const char*
tls_certificate_iterator_expiration_time (iterator_t*);

int
tls_certificate_iterator_valid (iterator_t *);

const char*
tls_certificate_iterator_certificate_format (iterator_t*);

const char*
tls_certificate_iterator_sha256_fingerprint (iterator_t*);

const char*
tls_certificate_iterator_serial (iterator_t*);

const char*
tls_certificate_iterator_last_seen (iterator_t*);

const char*
tls_certificate_iterator_time_status (iterator_t*);

int
tls_certificate_in_use (tls_certificate_t);

int
tls_certificate_writable (tls_certificate_t);

int
create_tls_certificate (const char *, const char *, const char *, int,
                        tls_certificate_t *);

int
copy_tls_certificate (const char*, const char*, const char*,
                      tls_certificate_t*);

int
modify_tls_certificate (const gchar *, const gchar *, const gchar *, int);

char*
tls_certificate_uuid (tls_certificate_t);

int
init_tls_certificate_source_iterator (iterator_t *, tls_certificate_t);

const char *
tls_certificate_source_iterator_uuid (iterator_t *);

const char *
tls_certificate_source_iterator_timestamp (iterator_t *);

const char *
tls_certificate_source_iterator_tls_versions (iterator_t *);

const char *
tls_certificate_source_iterator_location_uuid (iterator_t *);

const char *
tls_certificate_source_iterator_location_host_ip (iterator_t *);

const char *
tls_certificate_source_iterator_location_port (iterator_t *);

const char *
tls_certificate_source_iterator_origin_uuid (iterator_t *);

const char *
tls_certificate_source_iterator_origin_type (iterator_t *);

const char *
tls_certificate_source_iterator_origin_id (iterator_t *);

const char *
tls_certificate_source_iterator_origin_data (iterator_t *);

resource_t
get_or_make_tls_certificate_location (const char *, const char *);

resource_t
get_or_make_tls_certificate_origin (const char *, const char *, const char *);

resource_t
get_or_make_tls_certificate_source (tls_certificate_t,
                                    const char *,
                                    const char *,
                                    const char *,
                                    const char *,
                                    const char *);

char *
tls_certificate_host_asset_id (const char *, const char *);

#endif /* not _GVMD_MANAGE_TLS_CERTIFICATES_H */
