/* OpenVAS Manager
 * $Id$
 * Description: Splint helper headers for OpenVAS Manager.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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
void
g_free (/*@only@*/ /*@out@*/ /*@null@*/ gpointer mem);

gchar*
g_array_free (/*@only@*/ /*@out@*/ /*@null@*/ GArray *array,
              gboolean free_segment);

void
g_ptr_array_foreach (GPtrArray *array,
                     GFunc func,
                     /*@null@*/ gpointer user_data);

gchar*
g_base64_decode (const gchar *text, /*@out@*/ gsize *out_len);

typedef /*@out@*/ gchar* gchar_pointer;

gboolean
g_file_get_contents (const gchar *filename,
                     /*@out@*/ /* FIX maybe? */ gchar_pointer *contents,
                     /*@null@*/ /*@out@*/ gsize *length,
                     /*@null@*/ /*@out@*/ GError **error)
  /*@defines *contents*/;

/*@shared@*/ char*
uuid_error (uuid_rc_t error);

uuid_rc_t
uuid_create (/*@special@*/ uuid_t** uuid) /*@ensures notnull *uuid@*/;

typedef /*@null@*/ void* voidpointer;
uuid_rc_t
uuid_export (const uuid_t *uuid,
             uuid_fmt_t fmt,
             voidpointer* data,
             /*@null@*/ size_t* len);

/*@owned@*/ const char*
gnutls_alert_get_name (gnutls_alert_description_t alert);
/*@=incondefs@*/

/* FIX Weird that these are missing. */

int
strncasecmp (const char *s1, const char *s2, size_t n);

typedef /*@null@*/ struct dirent * dirent_pointer;
typedef /*@out@*/ /*@null@*/ dirent_pointer* dirent_pointer_pointer;

int
scandir (const char *dir, dirent_pointer_pointer *namelist,
         int(*filter)(const struct dirent *),
         int(*compar)(const struct dirent **, const struct dirent **))
  /*@defines *namelist@*/;

int
alphasort (const void *a, const void *b);

int
symlink (const char *oldpath, const char *newpath);
/*@=exportheader@*/

#endif /* !OPENVAS_MANAGER_SPLINT_H */
#endif /* S_SPLINT_S */
