#include <assert.h>
#include <math.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

typedef unsigned char uchar;

#define DISABLE_COLORS 

enum {
  RED = 31,
  GREEN = 32,
  YELLOW = 33,
  BLUE = 34,
};

typedef struct range_t {
  int start;
  int stop;
} range_t;

#define MAX_PATTERNS 64
#define MAX_REGEX_IN_PAT 128

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

typedef struct options {
  const char *i_filename;
  const char *o_filename;
  const char *rstr;
  const char *pattern[MAX_PATTERNS];
  /* bytes to replace a string with (used by search and replace -s) */
  const char *replace_str;
  int pattern_cnt;
  int base;
  bool extract;
  bool count;
  bool print;
  bool diff;
  bool snr;
  bool infuse;
} options_t;

typedef struct match_char {
  uchar *ptr;
  bool *any;
  int ptr_sz;
} match_char_t;

typedef struct match_t {
  /* TODO: use this as a union of range_t maybe? */ 
  match_char_t pat_bytes[MAX_PATTERNS];
  int pattern_cnt;
} match_t;

void match_init(match_t *m) {
  for (int i = 0; i < MAX_PATTERNS; ++i) {
    m->pat_bytes[i].ptr = NULL;
    m->pat_bytes[i].any = NULL;
    m->pat_bytes[i].ptr_sz = 0;
  }
  m->pattern_cnt = 0;
}

void match_free(match_t *m) {
  for (int i = 0; i < m->pattern_cnt; ++i) {
    free(m->pat_bytes[i].ptr);
    free(m->pat_bytes[i].any);
  }
}

void print_usage() {
  /* FIXME: update */
  printf("USAGE: \n");
  printf("Extract range bytes (in decimal) and write to outfile\n");
  printf("bed -e -b 10 -i filename -r 10-20 -o outfile\n\n");
  printf("Extract range bytes and write to outfile (any base can be specified)\n");
  printf("bed -e -b 16 -i filename -r ae-ffc -o outfile\n\n");
  printf("Extract bytes based on pattern and write to outfile\n");
  printf("bed -e -p '8c 41' -i infile -o outfile\n\n");
  printf("Specify multiple patterns to be extracted\n");
  printf("bed -e -p '8c 41' -p '1c 1c 1c' -p '9e 72 0a' -i infile -o outfile\n\n");
  printf("Count no of times a pattern occurs in a file\n");
  printf("bed -c -i filename -p '8c 7e'\n\n");
  printf("Pretty print a file\n");
  printf("bed -P -i filename\n\n");
  printf("Pretty print a raw from stdin\n");
  printf("bed -P -i -\n\n");
  // TODO: add a better syntax for bindiff
  printf("Diff two files (odd syntax i know)\n");
  printf("bed -D -i file1 -o file2\n\n");
  printf("Search and Replace a pattern. -s [replacepat] -p [searchpat]\n");
  printf("bed -s 'de de de de de' -p '08 0b' -i aa2 -o rep.vdb\n");
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

void append_pattern(options_t *options, const char *pattern) {
  if (options->pattern_cnt >= MAX_PATTERNS) {
    die("cant handle more than MAX_PATTERNS");
  }
  options->pattern[options->pattern_cnt++] = pattern;
}

void check_args(const options_t *options) {
  if (options->extract == 0 
      && options->count == 0
      && options->print == 0
      && options->diff == 0
      && options->snr == 0
      && options->infuse == 0) {
    die("Need an action flag (i.e. -e | -c | -p | -D | -s | -I)");
  }
  if (options->i_filename == NULL && options->o_filename == NULL) {
    die("need atleast input file or output file");
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
  options->print = 0;
  options->extract = 0;
  options->count = 0;
  options->diff = 0;
  options->snr = 0;
  options->infuse = 0;
}

void parse_args(int argc, char *argv[], options_t *options) {
  int opt;
  while ((opt = getopt(argc, argv, "hb:er:i:o:p:cPDs:I")) != -1) {
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
    case 'P':
      options->print = true;
      break;
    case 'c':
      options->count = true;
      break;
    case 'D':
      options->diff = true;
      break;
    case 's':
      options->snr = true;
      options->replace_str = optarg;
      break;
    case 'I':
      options->infuse = true;
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

void check_fp(FILE *fp, const char *msg) {
  if (fp == NULL) {
    die(msg);
  }
}

void extract_from_range(const char *ifile, const char *ofile, const char *range,
                        int base) {
  range_t rg = parse_range(range, base);
  FILE *fp = fopen(ifile, "r");
  check_fp(fp, "could not open file\n");
  FILE *ofp = NULL;
  if (strcmp(ofile, "-") == 0) {
    ofp = stdout;
  } else {
    ofp = fopen(ofile, "w");
    check_fp(ofp, "could not open file\n");
  }
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
    if (isalnum(*s) || *s == '.') {
      sz++;
    }
    s++;
  }
  assert(sz != 0 && "sz cannot be zero");
  assert(sz % 2 == 0 && "Invalid hex pattern, specify 0a instead of a");
  return sz / 2;
}


const char *create_ofilename(const char *filename, int suffix) {
  /* FIXME: make this non static, remove sprintf (very dangerous currently) */
#define OFSZ 256
  static char of[OFSZ];
  memset(of, '\0', OFSZ);
  sprintf(of, "%s-%d", filename, suffix);
  return of;
}

uchar *read_file(const char *filename, int *sz) {
  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    die("filename could not open file\n");
  }
  struct stat buf;
  stat(filename, &buf);
  *sz = buf.st_size;
  uchar *ret = (uchar *)malloc(*sz * sizeof(*ret));
  if (fread(ret, sizeof(*ret), *sz, fp) != (size_t) *sz) {
    die("cant fread");
  }
  fclose(fp);
  return ret;
}

void dump_to_file(const char *file, int suffix, const uchar *buf, int start,
                  int stop) {
  assert(file != NULL);
  FILE *fp = NULL;
  /* TODO: this is being repeated in extract_from_range() */
  if (strcmp(file, "-") == 0) {
    fp = stdout;
    fprintf(fp, "writing to stdout\n");
  } else {
    const char *suffxed_name = create_ofilename(file, suffix);
    fp = fopen(suffxed_name, "w");
  }
  for (int i = start; i < stop; ++i) {
    fputc(buf[i], fp);
  }
  fclose(fp);
}

/* remove whitespace */
const char *rmws(const char *ptr) {
  while (isspace(*ptr) && *ptr != '\0') {
    ptr++;
  }
  return ptr;
}

void pat2byte(match_t *m, const char *pattern, int n) {
  char *stop;
  for (int i = 0; i < m->pat_bytes[n].ptr_sz; ++i) {
    pattern = rmws(pattern);
    if (*pattern == '.' && *(pattern+1) == '.') {
      /* use vec_t */
      m->pat_bytes[n].any[i] = 1;
      pattern += 2;
    } else {
      m->pat_bytes[n].ptr[i] = strtol(pattern, &stop, 16);
      m->pat_bytes[n].any[i] = 0;
      pattern = stop;
    }
  }
}

void match_set_pat(match_t *m, const char *const *pattern) {
  for (int i = 0; i < m->pattern_cnt; ++i) {
    int sz = m->pat_bytes[i].ptr_sz;
    m->pat_bytes[i].ptr = (uchar *) malloc(sizeof(uchar) * sz);
    m->pat_bytes[i].any = (bool *) malloc(sizeof(bool) * sz);
    pat2byte(m, pattern[i], i);
  }
}

void match_set_pat_bytes(match_t *m, const char *const *pattern) {
  for (int i = 0; i < m->pattern_cnt; ++i) {
    m->pat_bytes[i].ptr_sz = getsz_from_pat(pattern[i]);
  }
}
void match_parse(match_t *m, const char *const *pattern, int pattern_cnt) {
  match_init(m);
  m->pattern_cnt = pattern_cnt;
  match_set_pat_bytes(m, pattern);
  match_set_pat(m, pattern);
}

void match_print(const match_t *m) {
  for (int i = 0; i < m->pattern_cnt; ++i) {
    const match_char_t *mm = &(m->pat_bytes[i]);
    for (int j = 0; j < mm->ptr_sz; ++j) {
      printf("%02x ", mm->ptr[j]);
    }
    printf("\n");
  }
}

bool lookahead_match(const uchar *hay, int hay_ptr, int hay_size,
                     const match_char_t *m) {
  if (hay_ptr >= hay_size) {
    return false;
  }
  if (hay_ptr + m->ptr_sz >= hay_size) {
    return false;
  }
  for (int i = 0; i < m->ptr_sz; ++i) {
    if (m->any[i]) {
      continue;
    }
    if (m->ptr[i] != hay[hay_ptr + i]) {
      return false;
    }
  }
  return true;
}


void extract_from_pattern(const char *i_filename, const char *o_filename,
                          const char *const *pattern, int pattern_cnt) {
  match_t match;
  match_parse(&match, pattern, pattern_cnt);

  vec_t match_indexes;
  vec_init(&match_indexes);

  int file_size = 0;
  uchar *file_arr = read_file(i_filename, &file_size);
  for (int i = 0; i < file_size; ++i) {
    for (int j = 0; j < match.pattern_cnt; ++j) {
      if (lookahead_match(file_arr, i, file_size, &(match.pat_bytes[j]))) {
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
  match_parse(&match, pattern, pattern_cnt);

  int match_cnt = 0;
  int file_size = 0;
  uchar *file_arr = read_file(i_filename, &file_size);
  for (int i = 0; i < file_size; ++i) {
    for (int j = 0; j < pattern_cnt; ++j) {
      if (lookahead_match(file_arr, i, file_size, &(match.pat_bytes[j]))) {
        printf("%d: ", i);
        for (int k = 0; k < match.pat_bytes[j].ptr_sz; ++k) {
          printf("%02x ", match.pat_bytes[j].ptr[k]);
        }
        printf("\n");
        match_cnt++;
      }
    }
  }
  if (match_cnt == 0) {
    exit(EXIT_FAILURE);
  }
  printf("Count: %d\n", match_cnt);
  free(file_arr);
}

/* print 'vicinity' characters on either side of 'index' in 'file_arr' */
void print_vicinity(const uchar *file_arr, int sz, int index, int vicinity
#ifndef DISABLE_COLORS
    , int color
#endif
    ) {
  /* clamp below */
  int low = (index - vicinity) < 0 ? 0 : (index - vicinity);
  /* clamp above */
  int high = (index + vicinity) >= sz ? sz : (index + vicinity);
  for (int i = low; i < high; ++i) {
#ifndef DISABLE_COLORS
    if (i == index) {
      printf("\033[%dm", RED);
    } else {
      printf("\033[%dm", color);
    }
#endif
    if (i == index) {
      printf("| 0x%02x %02x | ", file_arr[i], file_arr[i]);
    } else {
      printf("0x%02x ", file_arr[i]);
    }
#ifndef DISABLE_COLORS
    printf("\033[0m");
#endif
  }
}


void bindiff(const char *i_filename, const char *o_filename) {
  assert(i_filename != NULL);
  assert(o_filename != NULL);
  int f1_sz = 0;
  int f2_sz = 0;
  uchar *f1 = read_file(i_filename, &f1_sz);
  uchar *f2 = read_file(o_filename, &f2_sz);
  if (f1_sz != f2_sz) {
    printf("size do not match. f1_sz: %d, f2_sz: %d\n", f1_sz, f2_sz);
  }
  int min_sz = (f1_sz > f2_sz) ? f2_sz : f1_sz;
  for (int i = 0; i < min_sz; ++i) {
    if (f1[i] != f2[i]) {
      printf("mismatch at index %d\n", i);
      printf("file1: ");
      print_vicinity(f1, f1_sz, i, 10
#ifndef DISABLE_COLORS
          , YELLOW
#endif
          );
      printf("\n");
      printf("file2: ");
      print_vicinity(f2, f2_sz, i, 10
#ifndef DISABLE_COLORS
          , BLUE
#endif
          );
      printf("\n");
    }
  }
  free(f1);
  free(f2);
}

#define BYTES_ON_A_LINE 16
#define PRETTY_PRINT_ASCII

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c "

#define BYTE_TO_BINARY(byte)  \
  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0')

void printb(int c) {
  printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(c));
}

void pretty_print_aux(const char *i_filename) {
  int file_size = 0;
  uchar *file_arr = read_file(i_filename, &file_size);
  int lines = ceil((float) file_size / (float) BYTES_ON_A_LINE);
  for (int i = 0; i < lines; ++i) {
    printf("%08x\t", i * BYTES_ON_A_LINE);
    for (int j = 0; j < BYTES_ON_A_LINE; ++j) {
      int index = i * BYTES_ON_A_LINE + j;
      if (j % 8 == 0 && j != 0) {
        printf("| ");
      }
      if (index >= file_size) {
        break;
      }
      //printf("%02x ", file_arr[index]);
      printb(file_arr[index]);
    }
#ifdef PRETTY_PRINT_ASCII
    printf("\t");
    printf("|");
    for (int j = 0; j < BYTES_ON_A_LINE; ++j) {
      int index = i * BYTES_ON_A_LINE + j;
      if (file_arr[index] > 33 && file_arr[index] <= 126) {
        printf("%c", file_arr[index]);
      } else {
        printf(".");
      }
    }
    printf("|");
#endif
    printf("\n");
  }
  free(file_arr);
}

/* prints plain bytes from stdin */
void pretty_print_raw() {
  int c = 0;
  while ((c = getc(stdin)) != EOF) {
    printf("%02x ", c);
  }
}

void pretty_print(const options_t *options) {
  assert(options->i_filename != NULL && "input file not provided: use option -i");
  if (strcmp(options->i_filename, "-") == 0) {
    pretty_print_raw();
  } else {
    pretty_print_aux(options->i_filename);
  }
}

void push_rep(FILE *fp, const match_char_t *rep) {
  for (int i = 0; i < rep->ptr_sz; ++i) {
    fwrite(&(rep->ptr[i]), sizeof(uchar), 1, fp);
  }
}

void snr_pattern(const char *i_filename, const char *o_filename, const match_t *pats, const char *rep_str) {
  FILE *ofp = fopen(o_filename, "wb");
  if (!ofp) { die(strerror(errno)); }
  int ifarr_sz = 0;
  uchar *ifarr = read_file(i_filename, &ifarr_sz);
  match_t rep;
  match_parse(&rep, &rep_str, 1);
  for (int i = 0; i < ifarr_sz; ++i) {
    for (int j = 0; j < pats->pattern_cnt; ++j) {
      if (lookahead_match(ifarr, i, ifarr_sz, &(pats->pat_bytes[j]))) {
        push_rep(ofp, &(rep.pat_bytes[0]));
        i += pats->pat_bytes[j].ptr_sz;
        break;
      }
    }
    fwrite(&(ifarr[i]), sizeof(uchar), 1, ofp);
  }
  free(ifarr);
  fclose(ofp);
}

void snr(const options_t *options) {
  assert(options->i_filename != NULL);
  assert(options->o_filename != NULL);
  assert(options->replace_str != NULL);
  match_t pats;
  match_parse(&pats, options->pattern, options->pattern_cnt);
  snr_pattern(options->i_filename, options->o_filename, &pats, options->replace_str);
  /* TODO: consider adding snr_range? */
}

/* infuse: copy differentiating bytes from one file to another 
 * and write to stdout
 */
void infuse(const char *infusee_file, const char *infuser_file) {
  assert(infusee_file != NULL);
  assert(infuser_file != NULL);

  int infusee_sz = 0;
  uchar *infusee_arr = read_file(infusee_file, &infusee_sz);
  int infuser_sz = 0;
  uchar *infuser_arr = read_file(infuser_file, &infuser_sz);
  if (infusee_sz != infuser_sz) {
    return;
  }
  for (int i = 0; i < infusee_sz; ++i) {
    if (infusee_arr[i] != infuser_arr[i]) {
      fprintf(stdout, "%c", infuser_arr[i]); 
    } else {
      fprintf(stdout, "%c", infusee_arr[i]); 
    }
  }
}

void options_dispatch(const options_t *options) {
  if (options->rstr != NULL) {
    extract_from_range(options->i_filename, options->o_filename, options->rstr,
                       options->base);
  }
  if (options->pattern[0] != NULL && options->extract == 1) {

    extract_from_pattern(options->i_filename, options->o_filename,
                         options->pattern, options->pattern_cnt);
  }

  if (options->pattern[0] != NULL && options->count == 1) {
    count_patterns(options->i_filename, options->pattern, options->pattern_cnt);
  }

  if (options->print == 1) {
    pretty_print(options);
  }

  if (options->diff) {
    bindiff(options->i_filename, options->o_filename);
  }

  if (options->snr) {
    snr(options);
  }

  if (options->infuse) {
    infuse(options->i_filename, options->o_filename);
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
