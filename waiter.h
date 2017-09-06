#include <time.h>
#include <stdbool.h>
#include <signal.h>

extern sigset_t waiter_sigmask;

int waiter_setup(void);
void waiter_unblock(void);
bool waiter_wait(int signalfd, time_t sec);
void waiter_drain(int signalfd);
int waiter_next(int* status);
int waiter_fork(void);
void waiter_check(int status, bool timeout, int expected);
bool waiter_waitfor(int signalfd, time_t sec, int expected, int* status);
// # child processes still queued
int waiter_processes(void);
