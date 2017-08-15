int waiter_setup(void);
void waiter_unblock(void);
void waiter_drain(int signalfd);
int waiter_next(int* status);
int waiter_fork(void);
