NAME=qsmerge

INC=
LIB=-ltomcrypt -lc

DBGFLAGS=-g -fprofile-arcs -ftest-coverage

CPPFLAGS=${INC}
CFLAGS=-Wall -Wextra -Werror -std=c99 -pedantic ${CPPFLAGS} ${DBGFLAGS}
LDFLAGS=${DBGFLAGS}

CC?=gcc
LD=${CC}

HDR=error.h fmalloc.h
SRC=${NAME}.c error.c fmalloc.c
OBJ=${SRC:.c=.o}

.PHONY: all clean

all: ${NAME}

.c.o:
	${CC} ${CFLAGS} -c $<

${OBJ}: ${HDR}

${NAME}: ${OBJ}
	${LD} ${LDFLAGS} -o ${NAME} ${OBJ} ${LIB}

clean:
	rm -f ${OBJ} ${NAME} *.gcda *.gcno *.gcov
