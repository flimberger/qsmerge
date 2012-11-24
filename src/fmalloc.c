#include <stdlib.h>

#include "error.h"

void *
fcalloc(size_t n, size_t size)
{
	void *p;

	if (size == 0 || n == 0)
		return NULL;
	if ((p = calloc(n, size)) == NULL)
		die("Failed to reserve memory:");
	return p;
}

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

void *
frealloc(void *p, size_t size)
{
	if (size == 0)
		return p;
	if ((p = realloc(p, size)) == NULL)
		die("Failed to reserve memory:");
	return p;
}
