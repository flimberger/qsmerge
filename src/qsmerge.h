#ifndef _QSMERGE_H_
#define _QSMERGE_H_

typedef unsigned char uchar;
typedef unsigned int uint;

typedef struct {
	FILE *fp;
	char *name;
	uchar *hashes;
	size_t lines;
	size_t capacity;
} Input;

void setpname(char *name);
char *getpname(void);
void warn(const char *fmt, ...);
void die(const char *fmt, ...);
void panic(const char *fmt, ...);

#endif /* _QSMERGE_H_ */
