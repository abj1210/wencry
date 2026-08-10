#ifndef GETOPT_PORT_H
#define GETOPT_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

struct option
{
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

extern char *optarg;
extern int optind, opterr, optopt;

int getopt_long(int argc, char **argv, const char *optstring,
                const struct option *longopts, int *longindex);

#ifdef __cplusplus
}
#endif

#endif
