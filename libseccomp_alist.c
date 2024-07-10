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
  // SECCOMP 모드의 기본 값을 설정(초기화)
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
  // 임의의 시스템 콜(3번째 인자)을 허용하거나 거부할 수 있음
  seccomp_load(ctx);
  // 앞서 적용한 규칙을 애플리케이션에 반영
}


int banned() { fork(); }
int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  // 프로그램 실행 시 가장 먼저 sandbox 함수를 호출
  if (argc < 2) {
    banned();
  }
  // 전달된 인자가 2개 미만일 경우 banned 함수가 호출
  // 즉, SCMP_ACT_KILL에 의해 프로세스가 종료
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}

// FILTER_MODE: ALLOW LIST 예제 코드
// $ ./libseccomp_alist
// Bad system call (core dumped)
// $ ./libseccomp_alist 1
// ELF> J@X?@8	@@@?888h?h? P?P?!

// Seccomp 규칙이 올바르게 작동하고 있는지 판단 근거 2가지\
// 1. seccomp가 fork 시스템 콜을 차단해 fork 시스템 콜 호출 시 프로그램 종료
// 2. seccomp 규칙에 따라 허용된 open, read, write 시스템 콜을 성공적으로 실행
