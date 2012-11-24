#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tomcrypt.h>

#include "qsmerge.h"

enum {
	BUFSIZE = 1024 * 4,
	SHA1dlen = 20,	/* SHA-1 message digest length */
};

#define HASHSIZE(A)	((A) * SHA1dlen * sizeof(uchar))

static
void
fileopen(File *fs, char *filename)
{
	fs->name = filename;
	if ((fs->fp = fopen(fs->name, "r")) == NULL)
		die("Cannot open file %s:", fs->name);
}

static
void
fileclose(File *fs)
{
	if (fclose(fs->fp) != 0)
		die("Failed to close file %s:", fs->name);
}

static
void
hash(Hashtab *tab, File *fs)
{
	hash_state hs;
	uchar buf[BUFSIZE], *hash;
	size_t len;

	if ((tab->data = malloc(HASHSIZE(BUFSIZE))) == NULL)
		die("Failed to reserve memory:");
	tab->_maxcnt = BUFSIZE;
	tab->curcnt = 0;
	while (fgets((char *) buf, BUFSIZE, fs->fp) != NULL) {
		if (tab->curcnt == tab->_maxcnt) {
			if ((tab->data = realloc(tab->data, HASHSIZE(tab->_maxcnt) + HASHSIZE(BUFSIZE))) == NULL)
				die("Failed to reserve memory:");
			tab->_maxcnt += BUFSIZE;
		}
		hash = tab->data + tab->curcnt * SHA1dlen;
		sha1_init(&hs);
		len = strlen((char *) buf);
		sha1_process(&hs, buf, len);
		sha1_done(&hs, hash);
		tab->curcnt++;
	}
	if (ferror(fs->fp) != 0)
		die("Error on stream %s", fs->name);
	printf("\n");
}

static
uchar *
gethash(Hashtab *tab, size_t index)
{
	if (index > tab->curcnt)
		die("Hash index out of range");
	return tab->data + index * SHA1dlen;
}

static
bool
hashequals(uchar *a, uchar *b)
{
	uint i;

	for (i = 0; i < SHA1dlen; i++)
		if (*(a + i) != *(b + i))
			return false;
	return true;
}

static
void
copyhash(uchar *target, uchar *source)
{
	size_t i;

	for (i = 0; i < SHA1dlen; i++)
		*(target + i) = *(source + i);
}

static
void
findlcs(Hashtab *tab, Hashtab *a, Hashtab *b)
{
	size_t i, j, i2, j2, *l;

	if ((l = calloc((a->curcnt + 1) * (b->curcnt + 1), sizeof(size_t))) == NULL)
		die("Failed to reserve memory.");
	for (i = 0; i < a->curcnt + 1; i++) {
		for (j = 0; j < b->curcnt + 1; j++) {
			i2 = a->curcnt - i;
			j2 = b->curcnt - j;
			if (j2 < b->curcnt && i2 < a->curcnt) {
				if (hashequals(gethash(a, i2), gethash(b, j2)))
					l[i2 * (b->curcnt + 1) + j2] = 1 + l[(i2 + 1) * (b->curcnt + 1) + (j2 + 1)];
				else
					l[i2 * (b->curcnt + 1) + j2] = MAX(l[(i2 + 1) * (b->curcnt + 1) + j2], l[i2 * (b->curcnt + 1) + (j2 + 1)]);
			}
		}
	}
	if ((tab->data = malloc(HASHSIZE(MIN(a->curcnt, b->curcnt)))) == NULL)
		die("Failed to reserve memory.");
	tab->_maxcnt = MIN(a->curcnt, b->curcnt);
	tab->curcnt = 0;
	i = j = 0;
	while (i < a->curcnt && j < b->curcnt) {
		if (hashequals(gethash(a, i), gethash(b, j))) {
			copyhash(gethash(tab, tab->curcnt), gethash(a, i));
			i++;
			j++;
			tab->curcnt++;
		} else if (l[(i + 1) * (b->curcnt + 1) + j] >= l[i * (b->curcnt + 1) + (j + 1)])
			i++;
		else
			j++;
	}
	free(l);
}

static
void
merge(File *fo, File *fa, File *fb)
{
	size_t acnt, bcnt, a1cnt, b1cnt, lcnt;
	Hashtab o, a, b, a1, b1, lcs;
	char buf[BUFSIZE];

	hash(&o, fo);
	hash(&a, fa);
	hash(&b, fb);
	findlcs(&a1, &o, &a);
	findlcs(&b1, &o, &b);
	findlcs(&lcs, &a1, &b1);
	rewind(fa->fp);
	rewind(fb->fp);
	acnt = bcnt = a1cnt = b1cnt = lcnt = 0;
	while (acnt < a.curcnt || bcnt < b.curcnt) {
		/*
		 * case 1: a, b -> use a (or b)
		 * case 2: a, !b -> use b
		 * case 3: !a, b -> use a
		 * case 4: !a, !b -> conflict
		 */
		if (hashequals(gethash(&a, acnt), gethash(&b, bcnt))) {
			fgets(buf, BUFSIZE, fb->fp);
			fgets(buf, BUFSIZE, fa->fp);
			printf("%s", buf);
			acnt++;
			a1cnt++;
			bcnt++;
			b1cnt++;
			lcnt++;
		} else if (lcnt < lcs.curcnt && hashequals(gethash(&a, acnt), gethash(&lcs, lcnt))) {
			fgets(buf, BUFSIZE, fb->fp);
			printf("%s", buf);
			bcnt++;
		} else if (lcnt < lcs.curcnt && hashequals(gethash(&b, bcnt), gethash(&lcs, lcnt))) {
			fgets(buf, BUFSIZE, fa->fp);
			printf("%s", buf);
			acnt++;
		} else {
			if (acnt < a.curcnt && bcnt < b.curcnt) {
				if (hashequals(gethash(&a, acnt), gethash(&a1, a1cnt))) {
					fgets(buf, BUFSIZE, fa->fp);
					fgets(buf, BUFSIZE, fb->fp);
					printf("%s", buf);
					acnt++;
					a1cnt++;
					bcnt++;
				} else if (hashequals(gethash(&b, bcnt), gethash(&b1, b1cnt))) {
					fgets(buf, BUFSIZE, fb->fp);
					fgets(buf, BUFSIZE, fa->fp);
					printf("%s", buf);
					bcnt++;
					b1cnt++;
					acnt++;
				} else {
					fgets(buf, BUFSIZE, fa->fp);
					printf("<<<<<<< %s:%lu\n%s", fa->name, acnt + 1, buf);
					fgets(buf, BUFSIZE, fb->fp);
					printf("=======\n%s>>>>>>> %s:%lu", buf, fb->name, bcnt + 1);
					acnt++;
					bcnt++;
				}
			} else if (acnt < a.curcnt) {
				fgets(buf, BUFSIZE, fa->fp);
				printf("%s", buf);
				acnt++;
			} else { /* only b left */
				fgets(buf, BUFSIZE, fb->fp);
				printf("%s", buf);
				bcnt++;
			}
		}
	}
	free(lcs.data);
	free(b1.data);
	free(a1.data);
	free(b.data);
	free(a.data);
	free(o.data);
}

int
main(int argc, char *argv[])
{
	File forig, fain, fbin;

	setpname(argv[0]);
	if (argc < 4)
		die("Usage: %s ORIGFILE FILE1 FILE2");
	fileopen(&forig, argv[1]);
	fileopen(&fain, argv[2]);
	fileopen(&fbin, argv[3]);
	merge(&forig, &fain, &fbin);
	fileclose(&forig);
	fileclose(&fain);
	fileclose(&fbin);
	exit(0);
}
