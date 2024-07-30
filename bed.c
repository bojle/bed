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

#define MAX_PATTERNS 64

typedef struct options {
  const char *i_filename;
  const char *o_filename;
  const char *rstr;
  const char *pattern[MAX_PATTERNS];
  int pattern_cnt;
  int base;
  bool extract;
  bool count;
} options_t;

typedef struct match_t {
  /* TODO: use this as a union of range_t maybe? */ 
  uchar *pat_bytes[MAX_PATTERNS];
  int pat_bytes_sz[MAX_PATTERNS];
  /* indexes into pat_bytes that need to be treated
   * specially (like a regex)
   */
  //int *char_regex;
  int pattern_cnt;
} match_t;

void match_init(match_t *m) {
  for (int i = 0; i < MAX_PATTERNS; ++i) {
    m->pat_bytes[i] = NULL;
    m->pat_bytes_sz[i] = 0;
  }
  //m->char_regex = NULL;
  m->pattern_cnt = 0;
}

void match_free(match_t *m) {
  for (int i = 0; i < m->pattern_cnt; ++i) {
    free(m->pat_bytes[i]);
  }
  //free(m->char_regex);
}

void print_usage() {
  /* FIXME: update */
  printf("USAGE: \n"
         "bed -b 10 -e -i filename -r 10-20 -o outfile\n"
         "bed -e -p '8c 41' -i infile -o outfile\n"
         "bed -p '0a 0b 7e' -i filename -r 10-20 -o outfile\n"
         "bed -b 10 -i filename -r 10-20 -o outfile\n"
         "count no of times 8c 7e occurs in file\n"
         "bed -c -i filename -p \"8c 7e\"\n"
         "bed -b 16 -i filename -r ae-ffc -o outfile\n");
}

[[noreturn]] void help_and_die(const char *msg) {
  printf("%s\n", msg);
  print_usage();
  exit(EXIT_FAILURE);
}

[[noreturn]] void die(const char *msg) {
  printf("%s\n", msg);
  exit(EXIT_FAILURE);
}

void append_pattern(options_t *options, const char *pattern) {
  if (options->pattern_cnt >= MAX_PATTERNS) {
    die("cant handle more than MAX_PATTERNS");
  }
  options->pattern[options->pattern_cnt++] = pattern;
}

void check_args(const options_t *options) {
  if (options->extract == 0 && options->count == 0) {
    die("Need an action flag (i.e. -e | -c)");
  }
  if (options->i_filename == NULL && options->o_filename == NULL) {
    die("need both input file (-i) or output file (-o)");
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
  for (int i = 0; i < MAX_PATTERNS; ++i) {
    options->pattern[i] = NULL;
  }
  options->pattern_cnt = 0;
  options->base = 10;
  options->extract = 0;
  options->count = 0;
}

void parse_args(int argc, char *argv[], options_t *options) {
  int opt;
  while ((opt = getopt(argc, argv, "hb:er:i:o:p:c")) != -1) {
    switch (opt) {
      case 'h':
        print_usage();
        exit(EXIT_SUCCESS);
        break;
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
      append_pattern(options, optarg);
      break;
    case 'r':
      options->rstr = optarg;
      break;
    case 'b':
      options->base = strtol(optarg, NULL, 10);
      break;
    case 'c':
      options->count = true;
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

void extract_from_range(const char *ifile, const char *ofile, const char *range,
                        int base) {
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


const char *create_ofilename(const char *filename, int suffix) {
  /* FIXME: make this non static (very dangerous currently) */
  static char of[256];
  sprintf(of, "%s-%d", filename, suffix);
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

void pat2byte(uchar *pat_bytes, const char *pattern, int sz) {
  char *stop;
  for (int i = 0; i < sz; ++i) {
    pat_bytes[i] = strtol(pattern, &stop, 16);
    pattern = stop;
  }
}

void match_set_pat(match_t *m, const char *const *pattern) {
  for (int i = 0; i < m->pattern_cnt; ++i) {
    int sz = m->pat_bytes_sz[i];
    m->pat_bytes[i] = (uchar *) malloc(sizeof(*(m->pat_bytes[i])) * sz);
    pat2byte(m->pat_bytes[i], pattern[i], sz);
  }
}

void match_set_pat_bytes(match_t *m, const char *const *pattern) {
  for (int i = 0; i < m->pattern_cnt; ++i) {
    m->pat_bytes_sz[i] = getsz_from_pat(pattern[i]);
  }
}

void match_parse(match_t *m, const char *const *pattern, int pattern_cnt) {
  m->pattern_cnt = pattern_cnt;
  match_set_pat_bytes(m, pattern);
  match_set_pat(m, pattern);
}

bool lookahead_match(const uchar *hay, int hay_ptr, int hay_size,
                     const uchar *needle, int needle_size) {
  if (hay_ptr >= hay_size) {
    return false;
  }
  if (hay_ptr + needle_size >= hay_size) {
    return false;
  }
  for (int i = 0; i < needle_size; ++i) {
    if (needle[i] != hay[hay_ptr + i]) {
      return false;
    }
  }
  return true;
}

typedef struct vec_t {
  int *data;
  int size;
  int capacity;
} vec_t;

void vec_init(vec_t *vec) {
  vec->data = NULL;
  vec->size = 0;
  vec->capacity = 0;
}

void vec_push_back(vec_t *vec, int v) {
  if (vec->size >= vec->capacity) {
    vec->capacity = vec->capacity * 2 + 1;
    vec->data = realloc(vec->data, sizeof(int) * vec->capacity);
  }
  vec->data[vec->size++] = v;
}

int vec_at(vec_t *vec, int i) {
  assert(i < vec->size);
  return vec->data[i];
}

void vec_free(vec_t *vec) { free(vec->data); }

void extract_from_pattern(const char *i_filename, const char *o_filename,
                          const char *const *pattern, int pattern_cnt) {
  match_t match;
  match_init(&match);
  match_parse(&match, pattern, pattern_cnt);

  vec_t match_indexes;
  vec_init(&match_indexes);

  int file_size = 0;
  uchar *file_arr = read_file(i_filename, &file_size);
  for (int i = 0; i < file_size; ++i) {
    for (int j = 0; j < match.pattern_cnt; ++j) {
      if (lookahead_match(file_arr, i, file_size, match.pat_bytes[j],
                          match.pat_bytes_sz[j])) {
        vec_push_back(&match_indexes, i);
        printf("found a match for pattern %d at %d sz \n", j, i);
      }
    }
  }
  if (match_indexes.size == 0) {
    exit(EXIT_FAILURE);
  }

  int mindex = 0;
  int i;
  for (i = 0; i < match_indexes.size; ++i) {
    dump_to_file(o_filename, i, file_arr, mindex, vec_at(&match_indexes, i));
    mindex = vec_at(&match_indexes, i);
  }
  dump_to_file(o_filename, i, file_arr, mindex, file_size);

  free(file_arr);
  vec_free(&match_indexes);
  match_free(&match);
}

void count_patterns(const char *i_filename, const char *const *pattern,
                    int pattern_cnt) {
  match_t match;
  match_init(&match);
  match_parse(&match, pattern, pattern_cnt);

  int match_cnt = 0;
  int file_size = 0;
  uchar *file_arr = read_file(i_filename, &file_size);
  for (int i = 0; i < file_size; ++i) {
    for (int j = 0; j < pattern_cnt; ++j) {
      if (lookahead_match(file_arr, i, file_size, match.pat_bytes[j],
                          match.pat_bytes_sz[j])) {
        match_cnt++;
      }
    }
  }
  if (match_cnt == 0) {
    exit(EXIT_FAILURE);
  }
  printf("%d\n", match_cnt);
}

void options_dispatch(const options_t *options) {
  if (options->rstr != NULL) {
    extract_from_range(options->i_filename, options->o_filename, options->rstr,
                       options->base);
  }
  if (options->pattern != NULL && options->extract == 1) {
    extract_from_pattern(options->i_filename, options->o_filename,
                         options->pattern, options->pattern_cnt);
  }

  if (options->pattern != NULL && options->count == 1) {
    count_patterns(options->i_filename, options->pattern, options->pattern_cnt);
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
