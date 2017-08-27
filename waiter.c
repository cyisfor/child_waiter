#include "waiter.h"

#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/select.h> // pselect
#include <unistd.h> // read

#include <time.h>
#include <signal.h>
#include <error.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h> // abort
#include <stdio.h> // perror

static int child_processes = 0;

int waiter_setup(void) {
	// note still have to unblock SIGCHLD even when CLOEXEC is set!
	sigset_t child;
	sigemptyset(&child);
	sigaddset(&child,SIGCHLD);
	// waiter_fork may have been called before but the child died
	// SIG_BLOCK is the union of old mask and child, btw
	int res = sigprocmask(SIG_BLOCK,&child,NULL);
	assert(res == 0);
	// but signalfd only unmasks SIGCHLD, not any in oldmask
	return signalfd(-1, &child, SFD_NONBLOCK | SFD_CLOEXEC);
}

// call this in every child process before exec.
void waiter_unblock(void) {
	sigset_t child;
	sigemptyset(&child);
	sigaddset(&child,SIGCHLD);
	// unblock leaves signals not in child
	sigprocmask(SIG_UNBLOCK,&child,NULL);
}

// wait for JUST the signalfd to fire.
bool waiter_wait(int signalfd, time_t sec) {
	sigset_t child;
	sigemptyset(&child);
	sigaddset(&child,SIGCHLD);
	struct timespec timeout = {
		.tv_sec = sec
	};
	int res;
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(signalfd,&rfds);
SELECT_AGAIN: 
	res = pselect(signalfd+1,&rfds,NULL,NULL,&timeout, &child);
	if(res < 0) {
		switch(errno) {
		case EINTR:
			goto SELECT_AGAIN;
		};
		error(0,errno,"pselect");
		abort();
	}
	if(res == 0) return false; // timeout
	assert(res == 1);
	waiter_drain(signalfd);
	return true;
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
				return;
			};
			perror("drain");
			abort();
		}
		printf("%d\n",amt);
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
		// wut? isn't SIGCHLD blocked?
		if(errno == ECHILD) return 0;
		perror("waiter_next");
		abort();
	}
	--child_processes;
	return pid;
}

int waiter_fork(void) {
	int pid = fork();
	if(pid == 0) {
		waiter_unblock();
	} else {
		++child_processes;
	}
	return pid;
}

void waiter_check(int status, bool timeout, int expected) {
	if(timeout) {
		error(23,0,"timeout waiting for %d",expected);
	}
	if(!WIFEXITED(status)) {
		error(WTERMSIG(status),errno,"%d died with %d",expected,WTERMSIG(status));
	}
	if(0==WEXITSTATUS(status)) return;
	error(WEXITSTATUS(status),0,"%d exited with %d",expected,WEXITSTATUS(status));
}

bool waiter_waitfor(int signalfd, time_t sec, int expected, int *status) {
	assert(child_processes == 1);
	if(false == waiter_wait(signalfd, sec)) {
		return true;
	}
	int test = waiter_next(status);
	if(test != expected) {
		error(23,0,"wrong pid returned expected %d got %d",expected,test);
	}
	return false;
}

int waiter_processes(void) {
	return child_processes;
}
