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
	if ((set->hashes = calloc(BUFSIZE * SHA1MDS, sizeof(uchar))) == NULL)
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
	uint i;
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
		buf[len - 1] = '\0';
		printf("%s\t", buf);
		for (i = 0; i < SHA1MDS; i++)
			printf("%x", hash[i]);
		printf("\n");
		set->lines++;
	}
	if (ferror(set->fp) != 0)
		die("Error on stream %s", set->name);
	printf("\n\n");
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
	term(&orig);
	term(&in1);
	term(&in2);
	exit(0);
}
