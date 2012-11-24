#include <stdlib.h>

#include "error.h"

void *
fmalloc(size_t size)
{
	void *p;

	if (size == 0)
		return NULL;
	if ((p = malloc(size)) == NULL)
		die("Failed to reserve memory:");
	return p;
}
