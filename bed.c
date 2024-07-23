#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct range_t {
  int start;
  int stop;
} range_t;

typedef struct options {
  const char *filename;
  const char *rstr;
  int base;
} options_t;

void print_usage() {
  printf("USAGE: \n"
         "bed -b 10 -e filename -r 10-20\n"
         "bed -b 16 -e filename -r ae-ffc\n");
}

range_t parse_range(const char *rstr, int base) {
  range_t rg = {.start = 0, .stop = 0};
  char *stop_str;
  rg.start = strtol(rstr, &stop_str, base);
  rg.stop = strtol(stop_str + 1, NULL, base);
  assert(rg.stop >= rg.start &&
         "in range: stop ought to be greater/eq to start");
  return rg;
}

void die(const char *msg) {
  printf("%s\n", msg);
  print_usage();
  exit(EXIT_FAILURE);
}

void parse_args(int argc, char *argv[], options_t *options) {
  int opt;
  while ((opt = getopt(argc, argv, "b:e:r:")) != -1) {
    switch (opt) {
    case 'e':
      options->filename = optarg;
      break;
    case 'r':
      options->rstr = optarg;
      break;
    case 'b':
      options->base = strtol(optarg, NULL, 10);
      break;
    default:
      die("unknown or no arguments");
    }
  }
  if (!options->filename) {
    die("filename needed, use option -e");
  }
  if (!options->rstr) {
    die("filename needed, use option -r");
  }
}

void extract(const char *filename, const char *range, int base) {
  range_t rg = parse_range(range, base);
  FILE *fp = fopen(filename, "r");
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

int main(int argc, char *argv[]) {
  if (argc < 3) {
    die("too few arguments");
  }

  /* sane defaults */
  options_t options = {
    .filename = NULL,
    .rstr = NULL,
    .base = 10,
  };

  parse_args(argc, argv, &options);
  extract(options.filename, options.rstr, options.base);
}
