NAME=qsmerge

INC=
LIB=-ltomcrypt -lc

CPPFLAGS=
CFLAGS=-Wall -Wextra -Werror -std=c99 -pedantic ${CPPFLAGS} -g
LDFLAGS=-g

CC=gcc
LD=gcc

HDR=${NAME}.h
SRC=${NAME}.c error.c
OBJ=${SRC:.c=.o}

.PHONY: all clean

all: ${NAME}

.c.o:
	${CC} ${CFLAGS} -c $<

${OBJ}: ${HDR}

${NAME}: ${OBJ}
	${LD} ${LDFLAGS} -o ${NAME} ${OBJ} ${LIB}

clean:
	rm -f ${OBJ} ${NAME}
