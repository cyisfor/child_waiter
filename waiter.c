#include <sys/signalfd.h>
#include <signal.h>
#include <errno.h>

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

// call this to drain a signalfd, and then waiter_next until it returns 0
void waiter_drain(int signalfd) {
	struct signalfd_siginfo info;
	for(;;) {
		ssize_t amt = read(signalfd,&info,sizeof(info));
		if(amt == 0) break;
		if(amt < 0) {
			switch(errno) {
			case EINTR:
				continue;
			case EAGAIN:
				break;
			};
		}
		assert(amt == sizeof(info));
		assert(info.ssi_signo == SIGCHLD);
		/* ignore info.ssi_status, because a zombie process still needs to be reaped,
			 this is only the status of ONE of the multiple processes that triggered
			 this signal. Same goes for ssi_pid */
	}
}

// call until return 0, then select again, then drain
int waiter_next(int* status) {
	// SIGCHLD is blocked here, may get multiple children quitting though
	int pid = waitpid(-1,status,WNOHANG);
	if(pid == 0) return 0;
	if(pid < 0) {
		if(errno == ECHILD) return 0;
		perror("waiter_next");
		abort();
	}
	return pid;
}
