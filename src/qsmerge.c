#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tomcrypt.h>

#include "qsmerge.h"

enum {
	BUFSIZE = 1024 * 4,
	SHA1MDS = 20,	/* SHA-1 message digest size */
};

static Input orig, in1, in2;

static
void
init(Input *set, char *name)
{
	set->name = name;
	if ((set->fp = fopen(set->name, "r")) == NULL)
		die("Cannot open file %s:", set->name);
	if ((set->hashes = malloc(BUFSIZE * SHA1MDS * sizeof(uchar))) == NULL)
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
	size_t len;

	while (fgets((char *) buf, BUFSIZE, set->fp) != NULL) {
		if (set->lines <= set->capacity)
			if ((set->hashes = realloc(set->hashes, set->capacity += BUFSIZE)) == NULL)
				die("Failed to reserve memory:");
		hash = set->hashes + set->lines * SHA1MDS;
		sha1_init(&hs);
		len = strlen((char *) buf);
		sha1_process(&hs, buf, len);
		sha1_done(&hs, hash);
		set->lines++;
	}
	if (ferror(set->fp) != 0)
		die("Error on stream %s", set->name);
}

static
void
printhashes(Input *set)
{
	size_t i;
	uint j;

	for (i = 0; i < set->lines; i++) {
		for (j = 0; j < SHA1MDS; j++)
			printf("%x", *(set->hashes + i * SHA1MDS + j));
		printf("\n");
	}
	printf("\n");
}

static
bool
isemptyhash(uchar *h)
{
	uint i;

	for (i = 0; i < SHA1MDS; i++)
		if (*(h + i) != 0)
			return false;
	return true;
}

static
bool
hashequals(uchar *a, uchar *b)
{
	uint i;

	for (i = 0; i < SHA1MDS; i++)
		if (*(a + i) != *(b + i))
			return false;
	return true;
}

static
void
findlcs(Input *a, Input *b)
{
	char *l;
	size_t i, j, lines;
	uchar *lcs;
	uint k;

	if ((l = malloc(a->lines * b->lines)) == NULL)
		die("Failed to reserve memory:");
	for (i = a->lines; i > 0; i--)
		for (j = b->lines; j > 0; j--) {
			if (isemptyhash(a->hashes + SHA1MDS * i) && isemptyhash(b->hashes + SHA1MDS * j))
				l[i * a->lines + j] = 0;
			else if (hashequals((a->hashes + SHA1MDS * i), (b->hashes + SHA1MDS * j)))
				l[i * a->lines + j] = 1 + l[(i + 1) * a->lines + j + 1];
			else	/* the macro MAX is already defined at /usr/include/tomcrypt_macros.h:408 */
				l[i * a->lines + j] = MAX(l[(i + 1) * a->lines + j], l[i * a->lines + j + 1]);
		}
	if ((lcs = calloc(MAX(a->lines, b->lines), sizeof(uchar))) == NULL)
		die("Failed to reserve memory:");
	lines = j = i = 0;
	while (i < a->lines && j < b->lines) {
		if (hashequals(a->hashes + SHA1MDS * i, b->hashes + SHA1MDS * j)){
			for (k = 0; k < SHA1MDS; k++)
				*(lcs + lines * SHA1MDS + k) = *(a->hashes + SHA1MDS * i + k);
			lines++;
			j++;
			i++;
		} else if (l[(i + 1) * a->lines + j] >= l[i * a->lines + j + 1])
			i++;
		else
			j++;
	}
	for (i = 0; i < lines; i++) {
		for (k = 0; k < SHA1MDS; k++)
			printf("%x", *(lcs + i * SHA1MDS + k));
		printf("\n");
	}
	printf("\n");
	free(lcs);
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
	findlcs(&orig, &in2);
	printhashes(&orig);
	printhashes(&in1);
	printhashes(&in2);
	term(&orig);
	term(&in1);
	term(&in2);
	exit(0);
}
