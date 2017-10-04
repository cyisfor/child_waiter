#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>

const sigset_t* waiter_setup(void);
void waiter_unblock(void);
int waiter_wait(const sigset_t* sigmask, struct pollfd* poll, int npoll, time_t sec);
// call this to drain a signalfd, and then waiter_next until it returns 0
void waiter_drain(const sigset_t* sigmask);
int waiter_next(int* status);
int waiter_fork(void);
void waiter_check(int status, bool timeout, int expected);
// wait for JUST ONE process
// no other processes may exit during this time.
// returns true if timeout
bool waiter_waitfor(const sigset_t* sigmask, time_t timeout, int expected, int *status);

// # child processes still queued
int waiter_processes(void);
