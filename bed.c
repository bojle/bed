#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

typedef unsigned char uchar;

typedef struct range_t {
  int start;
  int stop;
} range_t;

typedef struct options {
  const char *i_filename;
  const char *o_filename;
  const char *rstr;
  const char *pattern;
  int base;
  bool extract;
} options_t;

void print_usage() {
  /* FIXME: update */
  printf("USAGE: \n"
         "bed -b 10 -e -i filename -r 10-20 -o outfile\n"
         "bed -e -p '8c 41' -i infile -o outfile\n"
         "bed -p '0a 0b 7e' -i filename -r 10-20 -o outfile\n"
         "bed -b 10 -i filename -r 10-20 -o outfile\n"
         "bed -b 16 -i filename -r ae-ffc -o outfile\n");
}

void help_and_die(const char *msg) {
  printf("%s\n", msg);
  print_usage();
  exit(EXIT_FAILURE);
}

void die(const char *msg) {
  printf("%s\n", msg);
  exit(EXIT_FAILURE);
}

void check_args(const options_t *options) {
  if (options->extract == 0) {
    die("Need an action flag (i.e. -e)");
  }
  if (options->i_filename == NULL && options->o_filename == NULL) {
    die("need both input file (-i) and output file (-o)");
  }
  if (options->pattern == NULL && options->rstr == NULL) {
    die("need atleast one of -r or -p");
  }
}

void init_options(options_t *options) {
  /* sane defaults */
  options->i_filename = NULL;
  options->o_filename = NULL;
  options->rstr = NULL;
  options->pattern = NULL;
  options->base = 10;
  options->extract = 0;
}

void parse_args(int argc, char *argv[], options_t *options) {
  int opt;
  while ((opt = getopt(argc, argv, "b:er:i:o:p:")) != -1) {
    switch (opt) {
    case 'e':
      options->extract = 1;
      break;
    case 'i':
      options->i_filename = optarg;
      break;
    case 'o':
      options->o_filename = optarg;
      break;
    case 'p':
      options->pattern = optarg;
      break;
    case 'r':
      options->rstr = optarg;
      break;
    case 'b':
      options->base = strtol(optarg, NULL, 10);
      break;
    default:
      help_and_die("unknown or no arguments");
    }
  }
  check_args(options);
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

inline void check_fp(FILE *fp, const char *msg) {
  if (fp == NULL) {
    die(msg);
  }
}

void extract_from_range(const char *ifile, const char *ofile, const char *range, int base) {
  range_t rg = parse_range(range, base);
  FILE *fp = fopen(ifile, "r");
  check_fp(fp, "could not open file\n");
  FILE *ofp = fopen(ofile, "w");
  check_fp(ofp, "could not open file\n");
  /* byte index */
  int bi = 0;
  int c;
  while ((c = fgetc(fp)) != EOF) {
    if (bi >= rg.start && bi < rg.stop) {
      fputc(c, ofp);
    }
    bi++;
  }
  fclose(fp);
  fclose(ofp);
}

/* returns total bytes required to store the pattern
 * pattern: "07 62 ae 8e b3 78 32"
 * return: 7
 */
int getsz_from_pat(const char *pattern) {
  const char *s = pattern;
  int sz = 0;
  while (*s != '\0') {
    if (isalnum(*s)) {
      sz++;
    }
    s++;
  }
  assert(sz % 2 == 0 && "Invalid hex pattern, specify 0a instead of a");
  return sz / 2;
}

void pat_to_bytes(const char *pattern, uchar *pat_bytes, int sz) {
  char *stop;
  for (int i = 0; i < sz; ++i) {
    pat_bytes[i] = strtol(pattern, &stop, 16);
    pattern = stop;
  }
}

const char *create_ofilename(const char *filename, int suffix) {
  /* FIXME: make this non static (very dangerous currently) */
  static char of[256];
  sprintf(of, "%s%d", filename, suffix);
  return of;
}

uchar *read_file(const char *filename, int *sz) {
  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    die("could not open file\n");
  }
  struct stat buf;
  stat(filename, &buf);
  *sz = buf.st_size;
  uchar *ret = (uchar *)malloc(*sz * sizeof(*ret));
  if (fread(ret, sizeof(*ret), *sz, fp) != *sz) {
    die("cant fread");
  }
  fclose(fp);
  return ret;
}

void dump_to_file(const char *file, int suffix, const uchar *buf, int start,
                  int stop) {
  const char *suffxed_name = create_ofilename(file, suffix);
  FILE *fp = fopen(suffxed_name, "w");
  for (int i = start; i < stop; ++i) {
    fputc(buf[i], fp);
  }
  fclose(fp);
}

void extract_from_pattern(const char *i_filename, const char *o_filename,
                          const char *pattern) {
  int sz = getsz_from_pat(pattern);
  uchar *pat_bytes = (uchar *)malloc(sizeof(*pat_bytes) * sz);
  pat_to_bytes(pattern, pat_bytes, sz);
  /* byte index */
  int bi = 0;
  int c;
  int mi = 0;
  bool in_match = false;
  bool previous_match = false;
  int match_start_bi = 0;
  int match_count = 0;
  int file_size = 0;
  int file_off_start = 0;

  uchar *file_arr = read_file(i_filename, &file_size);
  for (int bi = 0; bi < file_size; bi++) {
    if (previous_match == true && file_arr[bi] != pat_bytes[mi]) {
      mi = 0;
    }
    if (file_arr[bi] == pat_bytes[mi]) {
      mi++;
      if (mi >= sz) {
        dump_to_file(o_filename, match_count, file_arr, file_off_start,
                     match_start_bi);
        file_off_start = bi;
        // printf("found a match from %d to %d\n", match_start_bi, bi);
        match_count++;
        mi = 0;
      }
      previous_match = true;
      match_start_bi = bi;
    }
  }
  dump_to_file(o_filename, match_count, file_arr, match_start_bi, file_size);
  free(file_arr);
  free(pat_bytes);
  if (match_count == 0) {
    exit(EXIT_FAILURE);
  }
}

void options_dispatch(const options_t *options) {
  if (options->rstr != NULL) {
    extract_from_range(options->i_filename, options->o_filename, options->rstr, options->base);
  }
  if (options->pattern != NULL) {
    extract_from_pattern(options->i_filename, options->o_filename,
                         options->pattern);
  }
}

int main(int argc, char *argv[]) {
  if (argc < 1) {
    help_and_die("too few arguments");
  }

  options_t options;
  init_options(&options);
  parse_args(argc, argv, &options);
  options_dispatch(&options);
}
