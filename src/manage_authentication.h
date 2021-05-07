#ifndef _GVMD_MANAGE_AUTHENTICATION_H
#define _GVMD_MANAGE_AUTHENTICATION_H


enum manage_authentication_rc
{
  GMA_SUCCESS,
  GMA_HASH_VALID_BUT_DATED,
  GMA_HASH_INVALID,
  GMA_ERR,
};

enum manage_authentication_rc
manage_authentication_setup (const char *pepper, unsigned int pepper_size,
                             unsigned int count, char *prefix);
char *
manage_authentication_hash (const char *password);

enum manage_authentication_rc
manage_authentication_verify (const char *hash, const char *password);

#endif

