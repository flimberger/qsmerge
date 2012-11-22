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
	size_t len, i;

	if ((tab->data = malloc(HASHSIZE(BUFSIZE))) == NULL)
		die("Failed to reserve memory:");
	tab->maxcnt = BUFSIZE;
	tab->curcnt = 0;
	while (fgets((char *) buf, BUFSIZE, fs->fp) != NULL) {
		if (tab->curcnt == tab->maxcnt) {
			if ((tab->data = realloc(tab->data, HASHSIZE(tab->maxcnt) + HASHSIZE(BUFSIZE))) == NULL)
				die("Failed to reserve memory:");
			tab->maxcnt += BUFSIZE;
		}
		hash = tab->data + tab->curcnt * SHA1dlen;
		sha1_init(&hs);
		len = strlen((char *) buf);
		sha1_process(&hs, buf, len);
		sha1_done(&hs, hash);
		for (i = 0; i < SHA1dlen; i++)
			printf("%02x", *(hash + i));
		printf(" :: %s", buf);
		tab->curcnt++;
	}
	if (ferror(fs->fp) != 0)
		die("Error on stream %s", fs->name);
	printf("\n");
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
findlcs(Hashtab *tab, Hashtab *a, Hashtab *b)
{
	size_t i, j, i2, j2, *l;

	printf("lines: %lu, %lu\n", a->curcnt, b->curcnt);
	if ((l = calloc((a->curcnt + 1) * (b->curcnt + 1), sizeof(size_t))) == NULL)
		die("Failed to reserve memory.");
	for (i = 0; i < a->curcnt + 1; i++) {
		for (j = 0; j < b->curcnt + 1; j++) {
			i2 = a->curcnt - i;
			j2 = b->curcnt - j;
			if (j2 < b->curcnt && i2 < a->curcnt) {
				if (a->data[i * SHA1dlen] == a->data[j * SHA1dlen])
					l[i2 * (b->curcnt + 1) + j2] = 1 + l[(i2 + 1) * (b->curcnt + 1) + (j2 + 1)];
				else
					l[i2 * (b->curcnt + 1) + j2] = MAX(l[(i2 + 1) * (b->curcnt + 1) + j2], l[i2 * (b->curcnt + 1) + (j2 + 1)]);
			}
		}
	}
	for (i = 0; i < a->curcnt + 1; i++) {
		for (j = 0; j < b->curcnt + 1; j++)
			printf(" %3zu", l[i * (b->curcnt + 1) + j]);
		printf("\n");
	}
	if ((tab->data = malloc(HASHSIZE(MIN(a->curcnt, b->curcnt)))) == NULL)
		die("Failed to reserve memory.");
	tab->maxcnt = MIN(a->curcnt, b->curcnt);
	tab->curcnt = 0;
	i = j = 0;
	while (i < a->curcnt && i < b->curcnt) {
		if (hashequals(&a->data[i * SHA1dlen], &b->data[j * SHA1dlen])) {
			for (i2 = 0; i2 < SHA1dlen; i2++)
				tab->data[tab->curcnt * SHA1dlen + i2] = a->data[i * SHA1dlen + i2];
			i++;
			j++;
			tab->curcnt++;
		} else if (l[(i + 1) * (b->curcnt +1) + j] >= l[i * (b->curcnt +1) + (j + 1)])
			i++;
		else
			j++;
	}
	for (i = 0; i < tab->curcnt; i++) {
		for (j = 0; j < SHA1dlen; j++)
			printf("%02x", tab->data[i * SHA1dlen + j]);
		printf("\n");
	}
	free(l);
}

static
void
merge(File *fo, File *fa, File *fb)
{
	size_t ocnt, acnt, bcnt, i, line;
	Hashtab o, a, b, loa, lob;
	Line *out;
	char buf[BUFSIZE];

	hash(&o, fo);
	hash(&a, fa);
	hash(&b, fb);
	findlcs(&loa, &o, &a);
	findlcs(&lob, &o, &b);
	fprintf(stderr, "a lines: %lu\nb lines: %lu\n", loa.curcnt, lob.curcnt);
	if (loa.curcnt != lob.curcnt)
		die("Merge conflict detected: lcs of %s and %s are of different size", fa->name, fb->name);
	for (i = 0; i < loa.curcnt; i++)
		if (hashequals(&loa.data[i * SHA1dlen], &lob.data[i * SHA1dlen]) == false)
			die("Merge conflict detected: lcs of %s and %s differ", fa->name, fb->name);
	i = (o.curcnt + (a.curcnt - loa.curcnt) + (b.curcnt - lob.curcnt));
	/*
	 * I don't know why I need one additional element
	 * TODO: find out why
	 */
	if ((out = malloc((i + 1) * sizeof(Line))) == NULL)
		die("Failed to allocate memory");
	ocnt = acnt = bcnt = line = 0;
	while (ocnt <= o.curcnt) {
		if (hashequals(&a.data[acnt * SHA1dlen], &o.data[ocnt * SHA1dlen]) == true) {
			if (hashequals(&o.data[ocnt * SHA1dlen], &b.data[bcnt * SHA1dlen]) == false) {
				printf("b %lu: ", bcnt);
				for (i = 0; i < SHA1dlen; i++)
					printf("%02x", b.data[bcnt * SHA1dlen + i]);
				printf("\n");
				out[line].fromb = true;
				out[line].number = bcnt;
				line++;
				bcnt++;
			} else {
				printf("%lu-%lu: ", acnt, bcnt);
				for (i = 0; i < SHA1dlen; i++)
					printf("%02x", o.data[ocnt * SHA1dlen + i]);
				printf("\n");
				out[line].fromb = false;
				out[line].number = ocnt;
				line++;
				acnt++;
				bcnt++;
				ocnt++;
			}
		} else if (hashequals(&o.data[ocnt * SHA1dlen], &b.data[bcnt * SHA1dlen]) == true) {
			printf("a %lu: ", acnt);
			for (i = 0; i < SHA1dlen; i++)
				printf("%02x", a.data[acnt * SHA1dlen + i]);
			printf("\n");
			out[line].fromb = false;
			out[line].number = acnt;
			line++;
			acnt++;
		} else {
			die("Merge conflict detected: %s:%lu and %s:%lu differ", fa->name, acnt, fb->name, bcnt);
		}
	}
	acnt = bcnt = 0;
	rewind(fa->fp);
	rewind(fb->fp);
	for (i = 0; i < line; i++) {
		if (out[i].fromb == true) {
			while (bcnt < out[i].number) {
				fgets(buf, BUFSIZE, fb->fp);
				bcnt++;
			}
			printf("%s", buf);
		} else {
			while (acnt < out[i].number) {
				fgets(buf, BUFSIZE, fa->fp);
				acnt++;
			}
			printf("%s", buf);
		}
	}
	free(out);
	free(lob.data);
	free(loa.data);
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
