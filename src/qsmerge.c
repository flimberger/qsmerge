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

/*
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
*/

static
void
findlcs(Input *a, Input *b)
{
	size_t i, j, i2, j2, *l, var;

	printf("lines: %lu, %lu\n", a->lines, b->lines);
	if ((l = calloc((a->lines + 1) * (b->lines + 1), sizeof(size_t))) == NULL)
		die("Failed to reserve memory.");
	for (i = 0; i < a->lines + 1; i++) {
		for (j = 0; j < b->lines + 1; j++)
			printf(" %3zu", i * (b->lines + 1) + j);
		printf("\n");
	}
	printf("\n");
	for (i = 1; i <= a->lines; i++) {
		for (j = 1; j <= b->lines; j++) {
			i2 = a->lines - i;
			j2 = b->lines - j;
			printf(" %3zu", i2 + (j2 * a->lines));
			// l[i * b->lines + j] = i2 + (j2 * a->lines);
		}
		printf("\n");
	}
	printf("\n");
	for (i = 0; i < a->lines + 1; i++) {
		for (j = 0; j < b->lines + 1; j++) {
			if (j < b->lines && i < a->lines) {
				i2 = a->lines - 1 - i;
				j2 = b->lines - 1 - j;
				printf(" %-3zu", i2 + (j2 * a->lines));
				//l[i * (b->lines + 1) + j] = i2 + (j2 * a->lines);
			} else
				printf(" %-3zu", 0L);
		}
		printf("\n");
	}
	printf("\n");
	var = 0;
	for (i = 0; i < a->lines + 1; i++) {
		for (j = 0; j < b->lines + 1; j++) {
			i2 = a->lines - i;
			j2 = b->lines - j;
			if (j2 < b->lines && i2 < a->lines)
				l[i2 * (b->lines + 1) + j2] = var;
			var++;
		}
	}
	for (i = 0; i < a->lines + 1; i++) {
		for (j = 0; j < b->lines + 1; j++)
			printf(" %3zu", l[i * (b->lines + 1) + j]);
		printf("\n");
	}
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
