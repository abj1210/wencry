/*
POSIX getopt_long for platforms without it (e.g. Windows MSVC).
Self-contained C implementation following the classic getopt_long
algorithm (glibc/OpenBSD style). Used only when the system has no
getopt_long (Windows).
*/
#include "getopt_port.h"
#include <stdio.h>
#include <string.h>

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;

/* bounds of the run of non-options at the front of argv */
static int first_nonopt = 1;
static int last_nonopt = 1;
/* points at the next option character within the current argv element */
static char *place = NULL;

/*
exchange:将argv中前部非选项元素与选项元素交换位置
(实现选项重排,使非选项参数可出现在选项之后)
argv:命令行参数数组
*/
static void
exchange(char **argv)
{
  int bottom = first_nonopt;
  int middle = last_nonopt;
  int top = optind;
  char *tem;

  while (top > middle && middle > bottom)
  {
    if (top - middle > middle - bottom)
    {
      int len = middle - bottom;
      int i;
      for (i = 0; i < len; i++)
      {
        tem = argv[bottom + i];
        argv[bottom + i] = argv[top - (middle - bottom) + i];
        argv[top - (middle - bottom) + i] = tem;
      }
      top -= len;
    }
    else
    {
      int len = top - middle;
      int i;
      for (i = 0; i < len; i++)
      {
        tem = argv[bottom + i];
        argv[bottom + i] = argv[middle + i];
        argv[middle + i] = tem;
      }
      bottom += len;
    }
  }

  first_nonopt += (optind - last_nonopt);
  last_nonopt = optind;
}

/*
print_err:打印getopt错误信息(受opterr开关控制)
argv0:程序名
msg:错误描述
arg:相关的选项参数(可为NULL)
*/
static void
print_err(const char *argv0, const char *msg, const char *arg)
{
  if (opterr)
  {
    fprintf(stderr, "%s: %s", argv0, msg);
    if (arg && *arg)
      fprintf(stderr, " -- '%s'", arg);
    fprintf(stderr, "\n");
  }
}

/*
getopt_long:解析命令行长/短选项(POSIX getopt_long 的轻量实现)
参数与返回值说明见 getopt_port.h。
*/
int
getopt_long(int argc, char **argv, const char *optstring,
            const struct option *longopts, int *longindex)
{
  char c;
  const char *p;

  optarg = NULL;

  if (optind == 0)
    optind = 1;
  if (first_nonopt > optind)
    first_nonopt = optind;
  if (last_nonopt > optind)
    last_nonopt = optind;

  /* advance to the next option element */
  while (optind < argc && place == NULL)
  {
    char *elem = argv[optind];
    if (elem == NULL || elem[0] != '-' || elem[1] == '\0')
    {
    /* non-option element (or a lone '-') */
    if (elem != NULL && elem[0] == '-' && elem[1] == '\0')
    {
      optind++;
      return '-';
    }
    /* non-option: permute it towards the back and keep scanning */
    if (first_nonopt != last_nonopt)
      exchange(argv);
    else if (last_nonopt != optind)
    {
      first_nonopt = optind;
      last_nonopt = optind;
    }
    optind++;
    continue;
    }
    if (elem[1] == '-' && elem[2] == '\0')
    {
      /* bare "--": end of options */
      optind++;
      return -1;
    }
    /* this element is an option: point place at its first option char */
    place = elem + 1;
    if (*place == '-')
      place++; /* handle "--name" (long handled below) */
  }

  if (optind >= argc)
    return -1;

  /* long option: element starts with "--" and place points past them */
  if (place != NULL && place - argv[optind] >= 2)
  {
    const char *name = place;
    const char *nameend = name;
    const char *value = NULL;
    int i, match = -1, exact = 0, ambiguous = 0;
    int namelen;

    while (*nameend && *nameend != '=')
      nameend++;
    if (*nameend == '=')
      value = nameend + 1;
    namelen = (int)(nameend - name);

    for (i = 0; longopts && longopts[i].name; i++)
    {
      int n = (int)strlen(longopts[i].name);
      if (n < namelen || strncmp(name, longopts[i].name, namelen) != 0)
        continue;
      if (n == namelen)
      {
        exact = 1;
        match = i;
        break;
      }
      if (match == -1)
        match = i;
      else
        ambiguous = 1;
    }

    if (ambiguous && !exact)
    {
      print_err(argv[0], "option", name);
      print_err(argv[0], "is ambiguous", NULL);
      place = NULL;
      optind++;
      return '?';
    }
    if (match == -1)
    {
      print_err(argv[0], "unrecognized option", name);
      place = NULL;
      optind++;
      return '?';
    }

    optopt = longopts[match].val;

    if (longopts[match].has_arg == required_argument)
    {
      if (value != NULL)
        optarg = (char *)value;
      else if (optind + 1 < argc && argv[optind + 1] != NULL)
      {
        optind++;
        optarg = argv[optind];
      }
      else
      {
        print_err(argv[0], "option requires an argument", name);
        place = NULL;
        optind++;
        return optstring[0] == ':' ? ':' : '?';
      }
    }
    else if (longopts[match].has_arg == optional_argument)
    {
      optarg = (value != NULL) ? (char *)value : NULL;
    }
    else if (value != NULL)
    {
      print_err(argv[0], "option doesn't allow an argument", name);
      place = NULL;
      optind++;
      return '?';
    }

    if (longindex != NULL)
      *longindex = match;

    place = NULL;
    optind++;

    if (longopts[match].flag != NULL)
    {
      *longopts[match].flag = longopts[match].val;
      return 0;
    }
    return longopts[match].val;
  }

  /* short option (possibly clustered) */
  c = *place;
  p = strchr(optstring, c);

  if (p == NULL)
  {
    optopt = (unsigned char)c;
    {
      char buf[2] = {c, '\0'};
      print_err(argv[0], "invalid option", buf);
    }
    if (place[1] == '\0')
    {
      place = NULL;
      optind++;
    }
    else
      place++;
    return '?';
  }

  if (p[1] == ':')
  {
    /* option takes an argument */
    if (place[1] != '\0')
    {
      optarg = place + 1;
      place = NULL;
    }
    else if (optind + 1 < argc && argv[optind + 1] != NULL)
    {
      optind++;
      optarg = argv[optind];
      place = NULL;
    }
    else
    {
      optopt = (unsigned char)c;
      {
        char buf[2] = {c, '\0'};
        print_err(argv[0], "option requires an argument", buf);
      }
      place = NULL;
      optind++;
      return optstring[0] == ':' ? ':' : '?';
    }
    optind++;
  }
  else
  {
    /* no argument */
    place++;
    if (*place == '\0')
    {
      place = NULL;
      optind++;
    }
  }
  return (unsigned char)c;
}
