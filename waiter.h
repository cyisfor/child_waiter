#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>

void waiter_setup(void);
void waiter_unblock(void);
int waiter_pause(void);
int waiter_wait(struct pollfd* poll, int npoll, const struct timespec* timeout);
// call this to drain a signalfd, and then waiter_next until it returns 0
void waiter_drain(void);
int waiter_next(int* status);
int waiter_fork(void);
int waiter_fork(void);
void waiter_check(int status, bool timeout, int expected);
// wait for JUST ONE process
// no other processes may exit during this time.
// returns true if timeout
bool waiter_waitfor(const struct timespec* timeout, int expected, int *status);

// # child processes still queued
int waiter_processes(void);
