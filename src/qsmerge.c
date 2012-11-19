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

static Input orig, in1, in2;

static
void
init(Input *set, char *name)
{
	set->name = name;
	if ((set->fp = fopen(set->name, "r")) == NULL)
		die("Cannot open file %s:", set->name);
	if ((set->hashes = malloc(BUFSIZE * SHA1dlen * sizeof(uchar))) == NULL)
		die("Failed to reserve memory:");
	set->lines = 0;
	set->capacity = BUFSIZE;
}

static
void
term(Input *set)
{
	fclose(set->fp);
	free(set->hashes);
}

static
void
hash(Input *set)
{
	hash_state hs;
	uchar buf[BUFSIZE], *hash;
	size_t len, i;

	while (fgets((char *) buf, BUFSIZE, set->fp) != NULL) {
		if (set->lines <= set->capacity)
			if ((set->hashes = realloc(set->hashes, (set->capacity += (BUFSIZE * SHA1dlen * sizeof(uchar))))) == NULL)
				die("Failed to reserve memory:");
		hash = set->hashes + set->lines * SHA1dlen;
		sha1_init(&hs);
		len = strlen((char *) buf);
		sha1_process(&hs, buf, len);
		sha1_done(&hs, hash);
		for (i = 0; i < SHA1dlen; i++)
			printf("%02x", *(hash + i));
		printf(" :: %s", buf);
		set->lines++;
	}
	if (ferror(set->fp) != 0)
		die("Error on stream %s", set->name);
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
findlcs(Input *a, Input *b)
{
	size_t i, j, i2, j2, *l;
	uchar *seq;

	printf("lines: %lu, %lu\n", a->lines, b->lines);
	if ((l = calloc((a->lines + 1) * (b->lines + 1), sizeof(size_t))) == NULL)
		die("Failed to reserve memory.");
	for (i = 0; i < a->lines + 1; i++) {
		for (j = 0; j < b->lines + 1; j++) {
			i2 = a->lines - i;
			j2 = b->lines - j;
			if (j2 < b->lines && i2 < a->lines) {
				if (a->hashes[i * SHA1dlen] == a->hashes[j * SHA1dlen])
					l[i2 * (b->lines + 1) + j2] = 1 + l[(i2 + 1) * (b->lines + 1) + (j2 + 1)];
				else
					l[i2 * (b->lines + 1) + j2] = MAX(l[(i2 + 1) * (b->lines + 1) + j2], l[i2 * (b->lines + 1) + (j2 + 1)]);
			}
		}
	}
	for (i = 0; i < a->lines + 1; i++) {
		for (j = 0; j < b->lines + 1; j++)
			printf(" %3zu", l[i * (b->lines + 1) + j]);
		printf("\n");
	}
	if ((seq = calloc(MIN(a->lines, b->lines) * SHA1dlen, sizeof(uchar))) == NULL)
		die("Failed to reserve memory.");
	i = j = j2 = 0;
	while (i < a->lines && i < b->lines) {
		if (hashequals(&a->hashes[i * SHA1dlen], &b->hashes[j * SHA1dlen])) {
			for (i2 = 0; i2 < SHA1dlen; i2++)
				seq[j2 * SHA1dlen + i2] = a->hashes[i * SHA1dlen + i2];
			i++;
			j++;
			j2++;
		} else if (l[(i + 1) * (b->lines +1) + j] >= l[i * (b->lines +1) + (j + 1)])
			i++;
		else
			j++;
	}
	for (i2 = 0; i2 < j2; i2++) {
		for (i = 0; i < SHA1dlen; i++)
			printf("%02x", seq[i2 * SHA1dlen + i]);
		printf("\n");
	}
	free(seq);
	free(l);
}

int
main(int argc, char *argv[])
{
	setpname(argv[0]);
	if (argc < 4)
		die("Usage: %s ORIGFILE FILE1 FILE2");
	init(&orig, argv[1]);
	init(&in1, argv[2]);
	init(&in2, argv[3]);
	hash(&orig);
	hash(&in1);
	hash(&in2);
	findlcs(&orig, &in1);
	term(&orig);
	term(&in1);
	term(&in2);
	exit(0);
}
