#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define RANGE_BASE 10

typedef struct range_t {
  int start;
  int stop;
} range_t;

range_t parse_range(char *rstr) {
  range_t rg = {.start = 0, .stop = 0};
  char *stop_str;
  rg.start = strtol(rstr, &stop_str, RANGE_BASE);
  rg.stop = strtol(stop_str + 1, NULL, RANGE_BASE);
  assert(rg.stop >= rg.start &&
         "in range: stop ought to be greater/eq to start");
  return rg;
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    printf("too few arguments. ./a [file] [range]\n");
    exit(EXIT_FAILURE);
  }

  range_t rg = parse_range(argv[2]);
  FILE *fp = fopen(argv[1], "r");
  if (fp == NULL) {
    printf("could not open file\n");
  }
  /* byte index */
  int bi = 0;
  int c;
  while ((c = fgetc(fp)) != EOF) {
    if (bi >= rg.start && bi < rg.stop) {
      fputc(c, stdout);
    }
    bi++;
  }
}
