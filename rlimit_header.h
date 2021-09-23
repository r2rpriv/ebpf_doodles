#ifndef _RLIMIT_HEADER_H
#define _RLIMIT_HEADER_H
#include <sys/resource.h>

static __attribute__((constructor)) void bpf_rlimit_constructor(void)
{
  struct rlimit rlim_old,rlim_new =  {
      .rlim_cur = 128*(1<<20),
      .rlim_max = 128*(1<<20),
  };
  getrlimit(RLIMIT_MEMLOCK, &rlim_old);
  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new) < 0) {
    perror("Unable to lift memlock rlimit");
    rlim_new.rlim_cur = rlim_old.rlim_cur + (1UL << 20);
    rlim_new.rlim_max = rlim_old.rlim_max + (1UL << 20);
    setrlimit(RLIMIT_MEMLOCK, &rlim_new);
  }
}
#endif//_RLIMIT_HEADER_H
