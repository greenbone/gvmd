#ifndef _GVMD_MANAGE_SQL_SETTINGS_H
#define _GVMD_MANAGE_SQL_SETTINGS_H

#include "iterator.h"
#include "sql.h"

#include <glib.h>


typedef enum modify_setting_result
{
  MODIFY_SETTING_RESULT_ERROR = -1,
  MODIFY_SETTING_RESULT_OK = 0,
  MODIFY_SETTING_RESULT_NOT_FOUND,
  MODIFY_SETTING_RESULT_SYNTAX_ERROR,
  MODIFY_SETTING_RESULT_FEATURE_DISABLED,
  MODIFY_SETTING_RESULT_PERMISSION_DENIED = 99
} modify_setting_result_t;


int
setting_count (const char *);

int
setting_is_default_ca_cert (const gchar *);

char *
setting_filter (const char *);

int
setting_excerpt_size_int ();

void
init_setting_iterator (iterator_t *, const char *, const char *, int, int, int,
                       const char *);

const char *
setting_iterator_uuid (iterator_t*);

const char*
setting_iterator_name (iterator_t*);

const char*
setting_iterator_comment (iterator_t*);

const char*
setting_iterator_value (iterator_t*);

modify_setting_result_t
modify_setting (const gchar *, const gchar *, const gchar *, gchar **);

int
manage_modify_setting (GSList *, const db_conn_info_t *, const gchar *,
                       const gchar *, const char *);


#endif // _GVMD_MANAGE_SQL_SETTINGS_H
