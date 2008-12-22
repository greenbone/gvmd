/* Test strip_space with leading space. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../string.h"

int
main ()
{
  char string[6];
  char *expect = "abcd";

  strncpy (string, " abcd", 6);

  char* result = strip_space (string, string + 5);
  if (strlen (result) != 4 || strcmp (result, expect))
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
