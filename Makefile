bed: bed.c
	gcc -O3 -o bed $^

install: bed
	cp bed ${HOME}/.local/bin/

