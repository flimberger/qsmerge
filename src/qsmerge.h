#ifndef _QSMERGE_H_
#define _QSMERGE_H_

typedef unsigned char uchar;
typedef unsigned int uint;

typedef struct {
	size_t _maxcnt;	/* maximum count of hashes */
	size_t curcnt;	/* current count of hashes */
	uchar *data;	/* hash data */
} Hashtab;

typedef struct {
	FILE *fp;
	char *name;
} File;

typedef struct {
        bool fromb;
        size_t number;
} Line;

void setpname(char *name);
char *getpname(void);
void warn(const char *fmt, ...);
void die(const char *fmt, ...);
void panic(const char *fmt, ...);

#endif /* _QSMERGE_H_ */
