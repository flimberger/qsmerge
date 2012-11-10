#include <stdio.h>
#include <stdlib.h>

#include "qsmerge.h"

enum {
	BUFSIZE = 1024 * 4
};

int
main(int argc, char *argv[])
{
	char buf[BUFSIZE];
	char *orig, *in1, *in2;
	FILE *forig, *fin1, *fin2;

	setpname(argv[0]);
	if (argc < 4)
		die("Usage: %s ORIGFILE FILE1 FILE2");
	orig = argv[1];
	in1 = argv[2];
	in2 = argv[3];
	if ((forig = fopen(orig, "r")) == NULL)
		die("Cannot open file %s:", orig);
	if ((fin1 = fopen(in1, "r")) == NULL)
		die("Cannot open file %s:", in1);
	if ((fin2 = fopen(in2, "r")) == NULL)
		die("Cannot open file %s:", in2);
	while (fgets(buf, BUFSIZE, forig) != NULL)
		fputs(buf, stdout);
	if (ferror(forig) != 0)
		die("Error on stream %s", orig);
	while (fgets(buf, BUFSIZE, fin1) != NULL)
		fputs(buf, stdout);
	if (ferror(fin1) != 0)
		die("Error on stream %s", in1);
	while (fgets(buf, BUFSIZE, fin2) != NULL)
		fputs(buf, stdout);
	if (ferror(fin2) != 0)
		die("Error on stream %s", in2);
	fclose(fin2);
	fclose(fin1);
	fclose(forig);
	exit(0);
}
