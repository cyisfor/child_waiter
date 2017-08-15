#include <sys/signalfd.h>

int waiter_setup(void) {
	// note still have to unblock SIGCHLD even when CLOEXEC is set!
	sigset_t child;
	sigemptyset(&child);
	sigaddset(&child,SIGCHLD);
	// SIG_BLOCK is the union of old mask and child, btw
	int res = sigprocmask(SIG_BLOCK,&child,NULL);
	assert(res == 0);
	// but signalfd only unmasks SIGCHLD, not any in oldmask
	return = signalfd(-1, &child, SFD_NONBLOCK | SFD_CLOEXEC);
}

// call this in every child process before exec.

void waiter_unblock(void) {
	sigset_t child;
	sigemptyset(&child);
	sigaddset(&child,SIGCHLD);
	// unblock leaves signals not in child
	sigprocmask(SIG_UNBLOCK,&child,NULL);
}
	
