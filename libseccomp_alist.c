// Name: libseccomp_alist.c
// Compile: gcc -o libseccomp_alist libseccomp_alist.c -lseccomp
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  // SECCOMP 모드의 기본 값을 설정
  // 임의의 시스템 콜이 호출되면 이에 해당하는 이벤트가 발생

  if (ctx == NULL) {
    printf("seccomp error\n");
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  // SECCOMP의 규칙을 추가
  // 임의의 시스템 콜을 허용하거나 거부할 수 있음
  seccomp_load(ctx);
  // 앞서 적용한 규칙을 애플리케이션에 반영
}


int banned() { fork(); }
int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  if (argc < 2) {
    banned();
  }
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}

// FILTER_MODE: ALLOW LIST 예제 코드
// 
