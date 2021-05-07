#include "manage_authentication.h"
#include <gvm/util/passwordbasedauthentication.h>

#include <stdlib.h>
#include <string.h>

// prefer stack rather than heap so that we use the defaults on usage failure
// rather than having to check and fail.
struct PBASettings settings = {{0}, COUNT_DEFAULT, PREFIX_DEFAULT};

enum manage_authentication_rc
manage_authentication_setup (const char *pepper, unsigned int pepper_size,
                             unsigned int count, char *prefix)
{
  struct PBASettings *tmp = pba_init (pepper, pepper_size, count, prefix);
  enum manage_authentication_rc rc = GMA_ERR;
  unsigned int i;

  if (tmp == NULL)
    goto exit;
  // ovly override pepper when pepper is initially set otherwise keep
  // previous pepper
  for (i = 0; pepper != NULL && i < MAX_PEPPER_SIZE; i++)
    settings.pepper[i] = tmp->pepper[i];
  settings.count = count > 0 ? tmp->count : settings.count;
  settings.prefix = prefix != NULL ? tmp->prefix : settings.prefix;
  pba_finalize(tmp);
  rc = GMA_SUCCESS;

exit:
  return rc;
}

char *
manage_authentication_hash (const char *password)
{
    return pba_hash(&settings, password);
}

enum manage_authentication_rc
manage_authentication_verify (const char *hash, const char *password)
{
    enum pba_rc pba_rc = pba_verify_hash(&settings, hash, password);
    enum manage_authentication_rc rc;
    switch (pba_rc){
        case VALID:
            rc = GMA_SUCCESS;
            break;
        case INVALID:
            rc = GMA_HASH_INVALID;
            break;
        case UPDATE_RECOMMENDED:
            rc = GMA_HASH_VALID_BUT_DATED;
            break;
        default:
            rc = GMA_ERR;
            break;

    }

    return rc;
}

