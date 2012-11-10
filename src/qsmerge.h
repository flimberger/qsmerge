#ifndef _QSMERGE_H_
#define _QSMERGE_H_

void setpname(char *name);
char *getpname(void);
void warn(const char *fmt, ...);
void die(const char *fmt, ...);
void panic(const char *fmt, ...);

#endif /* _QSMERGE_H_ */
