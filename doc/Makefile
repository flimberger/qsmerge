NAME=Qualitätssicherung

LATEX=xelatex
BIBTEX=bibtex

SRC=${NAME}.tex algorithms.bib

.PHONY: all clean

${NAME}.pdf: ${SRC} qsmerge.man
	${LATEX} ${NAME}
	${BIBTEX} ${NAME}
	${LATEX} ${NAME}
	${LATEX} ${NAME}

qsmerge.man: ../man/man1/qsmerge.1
	# stupid groff thinks utf8 is latin1 ...
	groff -Tlatin1 -mandoc $< | col -b >$@

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.pdf *.toc qsmerge.man
