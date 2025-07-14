#include "debug_utils.h"
#include "manage_sql_oci_image_targets.h"
#include "manage_oci_image_targets.h"
#include "manage_acl.h"
#include "sql.h"
#include "utils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Create an OCI image target.
 *
 * @param[in]   name             Name of target.
 * @param[in]   comment          Comment on target.
 * @param[in]   credential_id    Credential for accessing the registry.
 * @param[in]   image_references Image OCI URLs
 * @param[out]  oci_image_target Created target.
 * @param[out]  error_message     Error message if any.
 *
 * @return 0 success, 1 target exists already, 2 error in image URLS,
 *         3 invalid credential, 4 could not find credential,
 *         5 invalid credential type, 99 permission denied, -1 error.
 */
int
create_oci_image_target (const char* name,
                         const char* comment,
                         const char* image_references,
                         const char *credential_id,
                         oci_image_target_t* oci_image_target,
                         gchar **error_message)
{
  gchar *quoted_name, *quoted_urls, *quoted_comment;
  oci_image_target_t new_oci_image_target;
  credential_t credential = 0;

  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (acl_user_may ("create_oci_image_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (resource_with_name_exists (name, "oci_image_target", 0))
    {
      sql_rollback ();
      return 1;
    }
  
  quoted_name = sql_quote (name ?: "");

  if (!validate_oci_image_references (image_references, error_message))
    {
      sql_rollback ();
      return 2;
    }

  quoted_urls = sql_quote (image_references);

  if (comment)
    quoted_comment = sql_quote (comment);
  else
    quoted_comment = sql_quote ("");

  if (credential_id)
    {
      if (strcmp (credential_id, "0"))
        {
          gchar *type;
          if (find_credential_with_permission (credential_id,
                                               &credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (credential == 0)
            {
              sql_rollback ();
              return 4;
            }

          type = credential_type (credential);
          if (strcmp (type, "up"))
            {
              sql_rollback ();
              return 5;
            }
          g_free (type);
        }
      else
        {
          sql_rollback ();
          return 3;
        }
    }

  sql ("INSERT INTO oci_image_targets"
       " (uuid, name, owner, image_references, comment,"
       "  creation_time, modification_time)"
       " VALUES (make_uuid (), '%s',"
       " (SELECT id FROM users WHERE users.uuid = '%s'),"
       " '%s', '%s', m_now (), m_now ());",
        quoted_name, current_credentials.uuid,
        quoted_urls, quoted_comment);

  new_oci_image_target = sql_last_insert_id ();

  if (credential)
    sql ("UPDATE oci_image_targets SET credential = %llu"
         " WHERE id = %llu;",
         credential,
         new_oci_image_target);

  if (oci_image_target)
    *oci_image_target = new_oci_image_target;

  g_free (quoted_comment);
  g_free (quoted_name);
  g_free (quoted_urls);

  sql_commit ();

  return 0;
}

/**
 * @brief Create an OCI image target from an existing one.
 *
 * @param[in]  name        Name of new target.  NULL to copy from existing.
 * @param[in]  comment     Comment on new target.  NULL to copy from existing.
 * @param[in]  oci_image_target_id   UUID of existing target.
 * @param[out] new_oci_image_target  New target.
 *
 * @return 0 success, 1 target exists already, 2 failed to find existing
 *         target, 99 permission denied, -1 error.
 */
int
copy_oci_image_target (const char* name,
                       const char* comment,
                       const char *oci_image_target_id,
                       oci_image_target_t* new_oci_image_target,
                       gchar **error_message)
{
  int ret;
  oci_image_target_t old_oci_image_target;

  assert (new_oci_image_target);

  ret = copy_resource ("oci_image_target", name, comment, oci_image_target_id,
                       "credential, image_references", 1, new_oci_image_target,
                       &old_oci_image_target);
  if (ret)
    return ret;

  return 0;
}

/**
 * @brief Modify an OCI image target.
 *
 * @param[in]   oci_image_target_id  UUID of target.
 * @param[in]   name                 Name of target.
 * @param[in]   comment              Comment on target.
 * @param[in]   credential_id        Credential.
 * @param[in]   image_references     List of image urls.
 * @param[out]  error_message        Error message if any.
 *
 * @return 0 success, 1 failed to find target, 
 *         2 zero length name, 3 target exists already,
 *         4 target is in use, 5 failed to find credential,
 *         6 invalid credential type, 7 error in image urls
 *         specification, 99 permission denied, -1 error.
 */
int
modify_oci_image_target (const char *oci_image_target_id, const char *name,
                         const char *comment, const char *credential_id,
                         const char *image_references, gchar **error_message)
{
  oci_image_target_t oci_image_target;
  credential_t credential;

  assert (oci_image_target_id);
  assert (current_credentials.uuid);

  sql_begin_immediate ();

  if (acl_user_may ("modify_oci_image_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  oci_image_target = 0;
  if (find_oci_image_target_with_permission (oci_image_target_id,
                                             &oci_image_target,
                                             "modify_oci_image_target"))
    {
      sql_rollback ();
      return -1;
    }

  if (oci_image_target == 0)
    {
      sql_rollback ();
      return 1;
    }

  if (name)
    {
      gchar *quoted_name;

      if (strlen (name) == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (resource_with_name_exists (name, "oci_image_target", oci_image_target))
        {
          sql_rollback ();
          return 3;
        }

      quoted_name = sql_quote (name);

      sql ("UPDATE oci_image_targets SET"
           " name = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_name,
           oci_image_target);

      g_free (quoted_name);
    }

  if (comment)
    {
      gchar *quoted_comment;
      quoted_comment = sql_quote (comment);

      sql ("UPDATE oci_image_targets SET"
           " comment = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_comment,
           oci_image_target);

      g_free (quoted_comment);
    }

  if (credential_id)
    {
      if (oci_image_target_in_use (oci_image_target))
        {
          sql_rollback ();
          return 4;
        }

      credential = 0;
      if (strcmp (credential_id, "0"))
        {
          gchar *type;
          if (find_credential_with_permission (credential_id,
                                               &credential,
                                               "get_credentials"))
            {
              sql_rollback ();
              return -1;
            }

          if (credential == 0)
            {
              sql_rollback ();
              return 5;
            }

          type = credential_type (credential);
          if (strcmp (type, "up"))
            {
              sql_rollback ();
              return 6;
            }
          g_free (type);

          sql ("UPDATE oci_image_targets SET"
              " credential = %llu,"
              " modification_time = m_now ()"
              " WHERE id = %llu;",
              credential,
              oci_image_target);
        }
      else
        sql ("UPDATE oci_image_targets SET"
             " credential = NULL,"
             " modification_time = m_now ()"
             " WHERE id = %llu;",
             oci_image_target);
    }

  if (image_references)
    {
      gchar *quoted_image_references;

      if (!validate_oci_image_references (image_references, error_message))
        {
          sql_rollback ();
          return 7;
        }

      quoted_image_references = sql_quote (image_references);

      sql ("UPDATE oci_image_targets SET"
           " image_references = '%s',"
           " modification_time = m_now ()"
           " WHERE id = %llu;",
           quoted_image_references,
           oci_image_target);

      g_free (quoted_image_references);
    }

  sql_commit ();

  return 0;
}

/**
 * @brief Delete an OCI image target.
 *
 * @param[in]  oci_image_target_id  UUID of target.
 * @param[in]  ultimate             Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a task refers to the target, 2 failed
 *         to find target, 99 permission denied, -1 error.
 */
int
delete_oci_image_target (const char *oci_image_target_id, int ultimate)
{
  oci_image_target_t oci_image_target = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_oci_image_target") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_oci_image_target_with_permission (oci_image_target_id,
                                             &oci_image_target,
                                             "delete_oci_image_target"))
    {
      sql_rollback ();
      return -1;
    }

  if (oci_image_target == 0)
    {
      if (find_trash ("oci_image_target", oci_image_target_id,
                      &oci_image_target))
        {
          sql_rollback ();
          return -1;
        }
      if (oci_image_target == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      /* Check if it's in use by a task in the trashcan. */
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE oci_image_target = %llu"
                   " AND oci_image_target_location = " 
                   G_STRINGIFY (LOCATION_TRASH) ";",
                   oci_image_target))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("oci_image_target", oci_image_target,
                               LOCATION_TRASH);
      tags_remove_resource ("oci_image_target", oci_image_target,
                            LOCATION_TRASH);

      sql ("DELETE FROM oci_image_targets_trash WHERE id = %llu;",
           oci_image_target);

      sql_commit ();
      return 0;
    }

  if (ultimate == 0)
    {
      if (sql_int ("SELECT count(*) FROM tasks"
                   " WHERE oci_image_target = %llu"
                   " AND oci_image_target_location = " 
                   G_STRINGIFY (LOCATION_TABLE)
                   " AND hidden = 0;",
                   oci_image_target))
        {
          sql_rollback ();
          return 1;
        }

      sql ("INSERT INTO oci_image_targets_trash"
           " (uuid, owner, name, image_references, comment,"
           "  credential, credential_location, creation_time,"
           "  modification_time)"
           " SELECT uuid, owner, name, image_references, comment,"
           " credential, " G_STRINGIFY (LOCATION_TABLE) ","
           " creation_time, modification_time"
           " FROM oci_image_targets WHERE id = %llu;",
           oci_image_target);

      /* Update the location of the target in any task. */
      sql ("UPDATE tasks"
           " SET oci_image_target = %llu,"
           "     oci_image_target_location = " 
           G_STRINGIFY (LOCATION_TRASH)
           " WHERE oci_image_target = %llu"
           " AND oci_image_target_location = " 
           G_STRINGIFY (LOCATION_TABLE) ";",
           sql_last_insert_id (),
           oci_image_target);

      permissions_set_locations ("oci_image_target", oci_image_target,
                                 sql_last_insert_id (),
                                 LOCATION_TRASH);
      tags_set_locations ("oci_image_target", oci_image_target,
                          sql_last_insert_id (),
                          LOCATION_TRASH);
    }
  else if (sql_int ("SELECT count(*) FROM tasks"
                    " WHERE oci_image_target = %llu"
                    " AND oci_image_target_location = "
                    G_STRINGIFY (LOCATION_TABLE),
                    oci_image_target))
    {
      sql_rollback ();
      return 1;
    }
  else
    {
      permissions_set_orphans ("oci_image_target", oci_image_target,
                               LOCATION_TABLE);
      tags_remove_resource ("oci_image_target", oci_image_target,
                            LOCATION_TABLE);
    }

  sql ("DELETE FROM oci_image_targets WHERE id = %llu;", oci_image_target);

  sql_commit ();
  return 0;
}

/**
 * @brief Try restore an OCI image target.
 *
 * If success, ends transaction for caller before exiting.
 *
 * @param[in]  oci_image_target_id  UUID of resource.
 *
 * @return 0 success, 1 fail because resource is in use, 2 failed to find
 *         resource, 3 fail because resource with same name exists,
 *         4 fail because resource with same UUID exists, -1 error.
 */
int
restore_oci_image_target (const char *oci_image_target_id)
{
  oci_image_target_t resource, oci_image_target;

  if (find_trash ("oci_image_target", oci_image_target_id, &resource))
    {
      sql_rollback ();
      return -1;
    }

  if (resource == 0)
    return 2;

  if (sql_int ("SELECT credential_location = " G_STRINGIFY (LOCATION_TRASH)
                " FROM oci_image_targets_trash WHERE id = %llu;",
                resource))
    {
      sql_rollback ();
      return 1;
    }

  if (sql_int ("SELECT count(*) FROM oci_image_targets"
               " WHERE name ="
               " (SELECT name FROM oci_image_targets_trash WHERE id = %llu)"
               " AND " ACL_USER_OWNS () ";",
               resource,
               current_credentials.uuid))
    {
      sql_rollback ();
      return 3;
    }

  if (sql_int ("SELECT count(*) FROM oci_image_targets"
               " WHERE uuid = (SELECT uuid"
               "               FROM oci_image_targets_trash"
               "               WHERE id = %llu);",
               resource))
    {
      sql_rollback ();
      return 4;
    }

  /* Move to "real" tables. */
  sql ("INSERT INTO oci_image_targets"
       " (uuid, owner, name, comment, creation_time, modification_time,"
       "  image_references, credential)"
       " SELECT"
       "  uuid, owner, name, comment, creation_time, modification_time,"
       "  image_references, credential"
       " FROM oci_image_targets_trash"
       " WHERE id = %llu;",
       resource);

  oci_image_target = sql_last_insert_id ();

  /* Update the oci image target in any tasks. */
  sql ("UPDATE tasks"
        " SET oci_image_target = %llu,"
        " oci_image_target_location = " G_STRINGIFY (LOCATION_TABLE)
        " WHERE oci_image_target = %llu"
        " AND oci_image_target_location = " G_STRINGIFY (LOCATION_TRASH),
        oci_image_target,
        resource);

  permissions_set_locations ("oci_image_target", resource, oci_image_target,
                             LOCATION_TABLE);
  tags_set_locations ("oci_image_target", resource, oci_image_target,
                      LOCATION_TABLE);

  /* Remove from trash tables. */

  sql ("DELETE FROM oci_image_targets_trash WHERE id = %llu;",
       resource);

  sql_commit ();
  return 0;
}

/**
 * @brief Filter columns for oci image target iterator.
 */
#define OCI_IMAGE_TARGET_ITERATOR_FILTER_COLUMNS               \
 { GET_ITERATOR_FILTER_COLUMNS, "image_references", "credential_name", NULL }

/**
 * @brief OCI Image Target iterator columns.
 */
#define OCI_IMAGE_TARGET_ITERATOR_COLUMNS                      \
 {                                                             \
   GET_ITERATOR_COLUMNS (oci_image_targets),                   \
   { "image_references", NULL, KEYWORD_TYPE_STRING },          \
   { "credential", NULL, KEYWORD_TYPE_INTEGER },               \
   {                                                           \
     "(SELECT name FROM credentials WHERE id = credential)",   \
     "credential_name",                                        \
     KEYWORD_TYPE_STRING                                       \
   },                                                          \
   { "0", NULL, KEYWORD_TYPE_INTEGER },                        \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                        \
 }

/**
 * @brief OCI Image Target iterator columns for trash case.
 */
#define OCI_IMAGE_TARGET_ITERATOR_TRASH_COLUMNS                         \
 {                                                                      \
   GET_ITERATOR_COLUMNS (oci_image_targets_trash),                      \
   { "image_references", NULL, KEYWORD_TYPE_STRING },                   \
   { "credential", NULL, KEYWORD_TYPE_INTEGER },                        \
   {                                                                    \
     "(SELECT CASE"                                                     \
     " WHEN credential_location = " G_STRINGIFY (LOCATION_TABLE)        \
     " THEN (SELECT name FROM credentials WHERE id = credential)"       \
     " ELSE (SELECT name FROM credentials_trash WHERE id = credential)" \
     " END)",                                                           \
     "credential_name",                                                 \
     KEYWORD_TYPE_STRING                                                \
   },                                                                   \
   { "credential_location", NULL, KEYWORD_TYPE_INTEGER },               \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                 \
 }

/**
 * @brief Count number of oci image targets.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of oci image targets in filtered set.
 */
int
oci_image_target_count (const get_data_t *get)
{
  static const char *extra_columns[] = OCI_IMAGE_TARGET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OCI_IMAGE_TARGET_ITERATOR_COLUMNS;
  static column_t trash_columns[] = OCI_IMAGE_TARGET_ITERATOR_TRASH_COLUMNS;
  return count ("oci_image_target", get, columns, trash_columns, extra_columns,
                0, 0, 0, TRUE);
}

/**
 * @brief Initialise an oci image target iterator, including observed targets.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find target, 2 failed to find filter,
 *         -1 error.
 */
int
init_oci_image_target_iterator (iterator_t* iterator, get_data_t *get)
{
  static const char *filter_columns[] = OCI_IMAGE_TARGET_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = OCI_IMAGE_TARGET_ITERATOR_COLUMNS;
  static column_t trash_columns[] = OCI_IMAGE_TARGET_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "oci_image_target",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get the image references of from an oci image target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Image references of the target or NULL if iteration is complete.
 */
DEF_ACCESS (oci_image_target_iterator_image_refs, GET_ITERATOR_COLUMN_COUNT);

/**
 * @brief Get the credential from an oci image target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Credential of the target of 0 if the iteration is complete.
 */
credential_t
oci_image_target_iterator_credential (iterator_t* iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int64 (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Get the Credential name from an oci image target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Credential name, or 0 if iteration is complete. Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (oci_image_target_iterator_credential_name, GET_ITERATOR_COLUMN_COUNT + 2);

/**
 * @brief Get the credential location of the oci image target from iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Location of the credential or 0 if iteration is complete.
 */
int
oci_image_target_iterator_credential_trash (iterator_t *iterator)
{
  if (iterator->done)
    return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Return the UUID of an OCI image target.
 *
 * @param[in]  oci_image_target  OCI image target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
oci_image_target_uuid (oci_image_target_t oci_image_target)
{
  return sql_string ("SELECT uuid FROM oci_image_targets"
                     " WHERE id = %llu;",
                     oci_image_target);
}

/**
 * @brief Return the UUID of a trashcan OCI image target.
 *
 * @param[in]  target  OCI image target.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
trash_oci_image_target_uuid (oci_image_target_t oci_image_target)
{
  return sql_string ("SELECT uuid FROM oci_image_targets_trash"
                     " WHERE id = %llu;",
                     oci_image_target);
}

/**
 * @brief Return the name of an OCI image target.
 *
 * @param[in]  target  OCI image target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
oci_image_target_name (oci_image_target_t oci_image_target)
{
  return sql_string ("SELECT name FROM oci_image_targets"
                     " WHERE id = %llu;",
                     oci_image_target);
}

/**
 * @brief Return the name of a trashcan OCI image target.
 *
 * @param[in]  target  OCI image target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_oci_image_target_name (oci_image_target_t oci_image_target)
{
  return sql_string ("SELECT name FROM oci_image_targets_trash"
                     " WHERE id = %llu;",
                     oci_image_target);
}

/**
 * @brief Return the comment of an OCI image target.
 *
 * @param[in]  oci_image_target  OCI image target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
oci_image_target_comment (oci_image_target_t oci_image_target)
{
  return sql_string ("SELECT comment FROM targets WHERE id = %llu;",
                     oci_image_target);
}

/**
 * @brief Return the comment of a trashcan OCI image target.
 *
 * @param[in]  oci_image_target  OCI image target.
 *
 * @return Newly allocated name if available, else NULL.
 */
char*
trash_oci_image_target_comment (oci_image_target_t oci_image_target)
{
  return sql_string ("SELECT comment FROM targets_trash WHERE id = %llu;",
                     oci_image_target);
}

/**
 * @brief Return whether a trashcan oci_image_target is readable.
 *
 * @param[in]  oci_image_target  OCI image target.
 *
 * @return 1 if readable, else 0.
 */
int
trash_oci_image_target_readable (oci_image_target_t oci_image_target)
{
  char *uuid;
  oci_image_target_t found = 0;

  if (oci_image_target == 0)
    return 0;
  uuid = oci_image_target_uuid (oci_image_target);
  if (find_trash ("oci_image_target", uuid, &found))
    {
      g_free (uuid);
      return 0;
    }
  g_free (uuid);
  return found > 0;
}

/**
 * @brief Return whether an oci image target is in use by a task.
 *
 * @param[in]  target  Target.
 *
 * @return 1 if in use, else 0.
 */
int
oci_image_target_in_use (oci_image_target_t oci_image_target)
{
  return !!sql_int ("SELECT count(*) FROM tasks"
                    " WHERE oci_image_target = %llu"
                    " AND oci_image_target_location = " 
                    G_STRINGIFY (LOCATION_TABLE)
                    " AND hidden = 0;",
                    oci_image_target);
}

/**
 * @brief Return whether a trashcan oci image target is referenced by a task.
 *
 * @param[in]  oci_image_target  OCI image target.
 *
 * @return 1 if in use, else 0.
 */
int
trash_oci_image_target_in_use (oci_image_target_t oci_image_target)
{
  return !!sql_int ("SELECT count(*) FROM tasks"
                    " WHERE oci_image_target = %llu"
                    " AND oci_image_target_location = " 
                    G_STRINGIFY (LOCATION_TRASH),
                    oci_image_target);
}

/**
 * @brief Initialise an oci image target task iterator.
 *
 * Iterates over all tasks that use the oci image target.
 *
 * @param[in]  iterator          Iterator.
 * @param[in]  oci_image_target  OCI image target.
 */
void
init_oci_image_target_task_iterator (iterator_t* iterator,
                                     oci_image_target_t oci_image_target)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (oci_image_target);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_tasks"));
  available = acl_where_owned ("task", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT name, uuid, %s FROM tasks"
                 " WHERE oci_image_target = %llu"
                 " AND hidden = 0"
                 " ORDER BY name ASC;",
                 with_clause ? with_clause : "",
                 available,
                 oci_image_target);

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the name from an oci image target task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the task, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (oci_image_target_task_iterator_name, 0);

/**
 * @brief Get the uuid from an oci image target_task iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The uuid of the task, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (oci_image_target_task_iterator_uuid, 1);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
oci_image_target_task_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}
