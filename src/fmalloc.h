#ifndef _FMALLOC_H_
#define _FMALLOC_H_

#include <stddef.h>

void *fmalloc(size_t size);
void *frealloc(void *p, size_t size);

#endif /* _FMALLOC_H_ */
