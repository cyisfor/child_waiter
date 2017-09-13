#define _GNU_SOURCE // ppoll
#include "waiter.h"
#include "note.h"
#include "mystring.h"

#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/poll.h> // ppoll
#include <unistd.h> // read

#include <time.h>
#include <error.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h> // abort
#include <stdio.h> // perror
#include <string.h>

static int child_processes = 0;
static int errout = -1;

sigset_t waiter_sigmask;

static void capture_err(void) {
	int io[2];
	pipe(io);
	errout = io[1];
	int pid = fork();
	if(pid != 0) {
		dup2(io[0],0);
		close(io[0]);
		close(io[1]);
		char buf[0x1000];
		size_t rpoint,wpoint = 0;
		for(;;) {
			ssize_t amt = read(0,buf+wpoint,0x1000-wpoint);
			if(amt <= 0) break;
			if(amt + wpoint == 0x1000) {
				write(2,LITLEN("OVERFLOW> "));
				write(2,buf+rpoint,wpoint-rpoint);
				write(2,LITLEN("\n"));
				rpoint = wpoint = 0;
				continue;
			}
			wpoint += amt;
			while(rpoint < wpoint) {
				char* nl = memchr(buf+rpoint,'\n',wpoint-rpoint);
				if(nl == NULL) break;
				write(2,LITLEN("> "));
				size_t nlamt = nl-(buf+rpoint);
				write(2,buf+rpoint,nlamt > 60 ? 60 : nlamt);
				write(2,LITLEN("\n"));
				rpoint += nlamt + 1;
				while(rpoint < wpoint && buf[rpoint] == '\n') {
					++rpoint;
				}
			}
		}
	}
	close(io[0]);
	INFO("redirecting error to %d\n",pid);
}


int waiter_setup(void) {
	capture_err();
	// note still have to unblock SIGCHLD even when CLOEXEC is set!
	sigemptyset(&waiter_sigmask);
	sigaddset(&waiter_sigmask,SIGCHLD);
// waiter_fork may have been called before but the child died
	// SIG_BLOCK is the union of old mask and child, btw
	int res = sigprocmask(SIG_BLOCK,&waiter_sigmask,NULL);
	assert(res == 0);
	// but signalfd only unmasks SIGCHLD, not any in oldmask
	return signalfd(-1, &waiter_sigmask, SFD_NONBLOCK | SFD_CLOEXEC);
}

// call this in every child process before exec.
void waiter_unblock(void) {
	// unblock leaves signals not in child
	sigprocmask(SIG_UNBLOCK,&waiter_sigmask,NULL);
}

// wait for JUST the signalfd to fire.
bool waiter_wait(struct pollfd* poll, int npoll, time_t sec) {
	struct timespec timeout = {
		.tv_sec = sec
	};
	int res;
POLL_AGAIN:
	res = ppoll(poll,1,&timeout, &waiter_sigmask);
	if(res < 0) {
		switch(errno) {
		case EINTR:
			goto POLL_AGAIN;
		};
		error(0,errno,"ppoll");
		abort();
	}
	if(res == 0) return false; // timeout
	assert(res == 1);
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
		if(errout >= 0) {
			dup2(errout,2);
			close(errout);
		}
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
	struct pollfd poll = {
		.fd = signalfd,
		.events = POLLIN
	};
	if(false == waiter_wait(&poll, 1, sec)) {
		return true;
	}
	waiter_drain(signalfd);
	int test = waiter_next(status);
	if(test != expected) {
		error(23,0,"wrong pid returned expected %d got %d",expected,test);
	}
	return false;
}

int waiter_processes(void) {
	return child_processes;
}

