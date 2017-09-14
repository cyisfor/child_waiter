#define _GNU_SOURCE // ppoll
#include "waiter.h"
#include "note.h"
#include "mystring.h"
#include "ensure.h"

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
#include <fcntl.h> // O_*
#include <stropts.h> // ioctl, IO_*

static int child_processes = 0;

sigset_t waiter_sigmask;

int errcapture = -1;

#define BUFSIZE 2048

static void capturing_err(void) {
	int fdpipe[2];
	pipe(fdpipe);
	int pid = fork();
	if(pid != 0) {
		close(fdpipe[0]);
		errcapture = fdpipe[1];
		return;
	}

	dup2(fdpipe[0],0);
	close(fdpipe[0]);
	close(fdpipe[1]);
	fcntl(0,F_SETFL,O_NONBLOCK);

	struct pollfd *sources = malloc(sizeof(struct pollfd));
	struct {
		struct {
			char s[5];
			int l;
		} pid;
		char* buf;
		int roff;
		int woff;
	} *infos = NULL;
	sources[0].fd = 0;
	sources[0].events = POLLIN; // POLLPRI?
	int nsources = 1;
	

	for(;;) {
		int n = ppoll(sources,nsources,NULL,NULL);
		if(n == 0) {
			error(errno,errno,"capture ppoll");
		}
		if(sources[0].revents & POLLIN) {
			int srcpid;
			for(;;) {
				ssize_t amt = read(sources[0].fd, &srcpid, sizeof(srcpid));
				if(amt == 0) {
					assert(errno == EAGAIN);
					break;
				}
				assert(amt == sizeof(srcpid));
				int srcerr;
				int res = ioctl(sources[0].fd, I_RECVFD, &srcerr);
				assert(res > 0);
				INFO("got new error source %d from %d",srcpid,srcerr);
				++nsources;
				sources = realloc(sources,sizeof(*sources) * nsources);
				infos = realloc(infos,sizeof(*infos) * (nsources-1));
				sources[nsources-1].fd = srcerr;
				sources[nsources-1].events = POLLIN;
				infos[nsources-2].pid.l = snprintf
					(infos[nsources-2].pid.s,5,"%d",srcpid);
				infos[nsources-2].buf = malloc(0x100);
				infos[nsources-2].roff = 0;
				infos[nsources-2].woff = 0;
			}
			continue;
		} 
		int i;
		void writeit(size_t amt) {
			write(2,infos[i-1].pid.s,infos[i-1].pid.l);
			write(2,LITLEN("> "));
			write(2,infos[i-1].buf+infos[i-1].roff,amt);
			write(2,LITLEN("\n"));
		}

		for(i=1;i<nsources;++i) {
			if(!(sources[i].revents & POLLIN)) continue;
			void writeit(size_t amt) {
				write(2,infos[i-1].pid.s,infos[i-1].pid.l);
				write(2,LITLEN("> "));
				write(2,infos[i-1].buf+infos[i-1].roff,amt);
				write(2,LITLEN("\n"));
			}
			for(;;) {
				ssize_t amt = read(sources[i].fd,
													 infos[i-1].buf + infos[i-1].woff,
													 BUFSIZE - infos[i-1].woff);
				if(amt == 0) break;
				if(amt < 0) {
					assert(errno == EAGAIN || errno == EINTR);
					break;
				}
				if(amt + infos[i-1].woff == BUFSIZE) {
					write(2,LITLEN("OVERFLOW "));
					writeit(BUFSIZE - infos[i-1].roff);
					infos[i-1].roff = infos[i-1].woff = 0;
				}
					 
				infos[i-1].woff += amt;
				while(infos[i-1].roff < infos[i-1].woff) {
					char* nl = memchr(infos[i-1].buf+infos[i-1].roff,
														'\n',
														infos[i-1].woff - infos[i-1].roff);
							
					if(nl == NULL) break;
					size_t nlamt = nl-(infos[i-1].buf + infos[i-1].roff);
					writeit(nlamt > 60 ? 60 : nlamt);
					infos[i-1].roff += nlamt + 1;
					while(infos[i-1].roff < infos[i-1].woff &&
								infos[i-1].buf[infos[i-1].roff] == '\n') {
						++infos[i-1].roff;
					}
				}
				if(infos[i-1].woff == infos[i-1].roff) {
					infos[i-1].woff = infos[i-1].roff = 0;
				} else if(infos[i-1].woff - infos[i-1].roff < infos[i-1].roff) {
					// can shift without overlap
					memcpy(infos[i-1].buf,
								 infos[i-1].buf+infos[i-1].roff,
								 infos[i-1].woff-infos[i-1].roff);
					infos[i-1].woff -= infos[i-1].roff;
					infos[i-1].roff = 0;
				}
			}
		}
	}

	abort();
}

static
void send_fd(int where, int pid, int fd) {
	ensure_eq(sizeof(pid), write(where,&pid,sizeof(pid)));
	ensure0(ioctl(where, I_SENDFD, fd));
}

static
void capture_err(void) {
	int io[2];
	pipe(io);
	send_fd(errcapture, getpid(), io[0]);
	close(io[0]);
	dup2(io[1],2);
	close(io[1]);
}


int waiter_setup(void) {
	capturing_err();
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
	static int level = 0;
	assert(level == 0);
	++level;
	int pid = fork();
	if(pid == 0) {
		capture_err();
		waiter_unblock();
	} else {
		++child_processes;
		--level;
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
