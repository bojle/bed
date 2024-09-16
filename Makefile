bed: bed.c
	gcc -O3 -Wall -Wextra -pedantic -std=c99 -o bed $^

debug: bed.c
	gcc -g -O3 -Wall -Wextra -pedantic -std=c99 -o bed $^

install: bed
	cp bed ${HOME}/.local/bin/

