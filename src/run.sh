#!/bin/sh

case "$1" in
fail)
	./qsmerge ../test/data/simple-dave.txt ../test/data/simple-orig.txt ../test/data/simple-mike.txt
	;;
nofail)
	./qsmerge ../test/data/simple-dave1.txt ../test/data/simple-orig.txt ../test/data/simple-mike.txt
	;;
*)
	./qsmerge ../test/data/simple-a.txt ../test/data/simple-orig.txt ../test/data/simple-b.txt
esac
