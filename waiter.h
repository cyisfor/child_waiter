#include <time.h>
#include <stdbool.h>

int waiter_setup(void);
void waiter_unblock(void);
bool waiter_wait(int signalfd, time_t sec);
void waiter_drain(int signalfd);
int waiter_next(int* status);
int waiter_fork(void);
void waiter_waitfor(int signalfd, time_t sec, int expected, bool check_status);
