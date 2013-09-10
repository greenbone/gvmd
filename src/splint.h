/* OpenVAS Manager
 * $Id$
 * Description: Splint helper headers for OpenVAS Manager.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef S_SPLINT_S
#ifndef OPENVAS_MANAGER_SPLINT_H
#define OPENVAS_MANAGER_SPLINT_H

/*@-exportheader@*/
/*@-incondefs@*/


/* GLib. */

/*@only@*/
gpointer
g_malloc (gsize n_bytes);

/*@only@*/
gpointer
g_malloc0 (gsize n_bytes);

void
g_free (/*@only@*/ /*@out@*/ /*@null@*/ gpointer mem);

void
g_error_free (/*@only@*/ /*@out@*/ /*@null@*/ GError* error);

gchar*
g_array_free (/*@only@*/ /*@out@*/ /*@null@*/ GArray *array,
              gboolean free_segment);

gchar*
g_ptr_array_free (/*@only@*/ /*@out@*/ /*@null@*/ GPtrArray *array,
                  gboolean free_segment);

void
g_ptr_array_add (/*@only@*/ GPtrArray *array,
                 /*@keep@*/ gpointer data);

/*@only@*/
GSList*
g_slist_append (/*@keep@*/ GSList* list, /*@keep@*/ gpointer data);

/** @todo These "keep"s depend on g_hash_table_new params. */
void
g_hash_table_insert (GHashTable *hash_table,
                     /*@keep@*/ gpointer key,
                     /*@keep@*/ gpointer value);

void
g_hash_table_destroy (/*@only@*/ GHashTable *hash_table);

void
g_ptr_array_foreach (GPtrArray *array,
                     GFunc func,
                     /*@null@*/ gpointer user_data);

guchar*
g_base64_decode (const gchar *text, /*@out@*/ gsize *out_len);

typedef /*@out@*/ gchar* gchar_pointer;

gboolean
g_file_get_contents (const gchar *filename,
                     /*@out@*/ /** @todo Maybe? */ gchar_pointer *contents,
                     /*@null@*/ /*@out@*/ gsize *length,
                     /*@null@*/ /*@out@*/ GError **error)
  /*@defines *contents*/;

typedef /*@null@*/ GError * gerrorpointer;

gboolean
g_file_set_contents (const gchar *filename,
                     const gchar *contents,
                     gssize length,
                     /*@null@*/ gerrorpointer* error);

/*@notnull@*/ gchar*
g_build_filename (const gchar *first, ...);

/*@dependent@*/ const gchar*
g_dir_read_name (GDir *dir);

/*@dependent@*/ const gchar*
g_dir_close (/*@only@*/ /*@out@*/ GDir *dir);

/*@only@*/ GRand*
g_rand_new ();

void
g_rand_free (/*@only@*/ /*@out@*/ GRand *);

void
g_strfreev (/*@only@*/ /*@out@*/ gchar **);

void
g_key_file_free (/*@only@*/ /*@out@*/ GKeyFile *);

void
g_string_free (/*@only@*/ /*@out@*/ GString *, gboolean);

void
g_option_context_free (/*@only@*/ /*@out@*/ GOptionContext *);


/* GNUTLS. */

#include <gnutls/gnutls.h>

/*@owned@*/ const char*
gnutls_alert_get_name (gnutls_alert_description_t alert);


/* Standard functions. */

typedef /*@null@*/ struct dirent * dirent_pointer;
typedef /*@null@*/ dirent_pointer* dirent_pointer_pointer;

int
scandir (const char *dir, dirent_pointer_pointer *namelist,
         /*@null@*/ int(*filter)(const struct dirent *),
         int(*compar)(const struct dirent **, const struct dirent **))
  /*@allocates *namelist@*/;

int
alphasort (const void *a, const void *b);

/*@=incondefs@*/
/*@=exportheader@*/

#endif /* !OPENVAS_MANAGER_SPLINT_H */
#endif /* S_SPLINT_S */
