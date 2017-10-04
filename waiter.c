#define _GNU_SOURCE // ppoll
#include "waiter.h"
#include "note.h"
#include "mystring.h"
#include "ensure.h"

#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/poll.h> // ppoll
#include <sys/socket.h>

#include <unistd.h> // read
#include <stdarg.h> // va_*

#include <time.h>
#include <error.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h> // abort
#include <stdio.h> // perror
#include <string.h>
#include <fcntl.h> // O_*


static int child_processes = 0;

int errcapture = -1;

#define BUFSIZE 2048

static
void report(int revents, const char* fmt, ...) {
	fprintf(stderr, ">%d ",getpid());
	fwrite(LITLEN("REPORT "),1,stderr);
	va_list arg;
	va_start(arg, fmt);
	vfprintf(stderr,fmt,arg);
	if(revents & POLLERR) {
		fwrite(LITLEN(" error"),1,stderr);
	} else if(revents & POLLNVAL) {
		fwrite(LITLEN(" invalid socket"),1,stderr);
	} else if(revents & POLLHUP) {
		fwrite(LITLEN(" hung up.\n"),1,stderr);
		fflush(stderr);
		return;
	} else {
		fwrite(LITLEN(" unknown!"),1,stderr);
	}
	fwrite(LITLEN(" with events "),1,stderr);
	fprintf(stderr,"%x\n", revents);
	fflush(stderr);
}

static void capturing_err(void) {
	/* copyright trolls bullied linux into not supporting I_SENDFD
		 so we need to use the more complicated socket based method
	*/
	int socks[2];
	ensure0(socketpair(AF_UNIX,SOCK_SEQPACKET,0,socks))
	int pid = fork();
	if(pid != 0) {
		close(socks[0]);
		errcapture = socks[1];
		return;
	}
	fprintf(stderr, "capturing error with %d\n",getpid());
	close(socks[1]);
	dup2(socks[0],0);
	close(socks[0]);
	fcntl(0,F_SETFL,fcntl(0,F_GETFL)|O_NONBLOCK);

	struct pollfd *sources = malloc(sizeof(struct pollfd));
	struct {
		struct {
			char s[6];
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
		if(sources[0].revents == POLLIN) {
			for(;;) {
				int srcpid;
				int srcerr;
				struct msghdr msg = {0};
				struct iovec io = { .iov_base = &srcpid, .iov_len = sizeof(srcpid) };
				msg.msg_iov = &io;
				msg.msg_iovlen = 1;

				char c_buffer[256];
				msg.msg_control = c_buffer;
				msg.msg_controllen = sizeof(c_buffer);

				int res = recvmsg(0, &msg, 0);
				if(res <= 0) {
					ensure_eq(errno,EAGAIN);
					break;
				}
				ensure_gt(res,0);

				struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

				// memcpy to avoid alignment issues, I guess?
				memcpy(&srcerr, CMSG_DATA(cmsg), sizeof(srcerr));

				INFO("got new stderr source %d from %d",srcerr,srcpid);
				++nsources;
				sources = realloc(sources,sizeof(*sources) * nsources);
				infos = realloc(infos,sizeof(*infos) * (nsources-1));
				sources[nsources-1].fd = srcerr;
				sources[nsources-1].events = POLLIN;
				infos[nsources-2].pid.l = snprintf
					(infos[nsources-2].pid.s,6,"%d",srcpid);
				infos[nsources-2].buf = malloc(0x100);
				infos[nsources-2].roff = 0;
				infos[nsources-2].woff = 0;
				srcpid = -1;
			}
			continue;
		} else if(sources[0].revents) {
			// something went wrong!
			report(sources[0].revents,"ppoll socket");
			exit(0);
		}

		int i;
		void writeit(size_t amt) {
			write(2,infos[i-1].pid.s,infos[i-1].pid.l);
			write(2,LITLEN("> "));
			write(2,infos[i-1].buf+infos[i-1].roff,amt);
			write(2,LITLEN("\n"));
		}

		for(i=1;i<nsources;++i) {
			if(sources[i].revents == 0) continue;
			if(sources[i].revents != POLLIN) {
				report(sources[i].revents,"source %d:%.*s",i,infos[i].pid.l,infos[i].pid.s);
				close(sources[i].fd);
				sources[i].fd = -1;
				sources[i].events = 0;
				continue;
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
	struct msghdr msg = {};
	char buf[CMSG_SPACE(sizeof(fd))];
	memset(buf, '\0', sizeof(buf));

  struct iovec io = { .iov_base = &pid, .iov_len = sizeof(pid) };

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
	// "this is a socket we're sending" = SCM_RIGHTS
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	msg.msg_controllen = cmsg->cmsg_len;

	ensure_ge (sendmsg(where, &msg, 0), 0);
}

static
void capture_err(void) {
	ensure_ge(errcapture,0);
	int io[2];
	pipe(io);
	send_fd(errcapture, getpid(), io[0]);
	close(io[0]);
	dup2(io[1],2);
	close(io[1]);
}

/* the original signal mask could have blocked SIGCHLD
	 so if we pass the orginal signal mask to ppoll... it doesn't EINTR for child processes.
	 So we need to pass the original mask to forked processes, but to ppoll we must pass the
	 original mask, explicitly minus SIGCHLD.

	 And to sigtimedwait, we must pass a sigset_t containing only SIGCHLD, so we need three
	 different sigset_t's.
*/


struct {
	static sigset_t original;
	static sigset_t nochild;
	static sigset_t onlychild;
} mask;

void waiter_setup(void) {
	sigemptyset(&mask.onlychils);
	sigaddset(&mask.onlychild,SIGCHLD);

	capturing_err();
	// note still have to unblock SIGCHLD even when CLOEXEC is set!
	
// waiter_fork may have been called before but the child died
	// SIG_BLOCK is the union of old mask and child, btw
	int res;
	res = sigprocmask(SIG_SETMASK,NULL, &mask.nochild);
	assert(res == 0);
	sigdelset(&mask.nochild, SIGCHLD);

	res = sigprocmask(SIG_BLOCK,&mask.add, &mask.original);
	assert(res == 0);		 
}

// call this in every child process before exec.
void waiter_unblock(void) {
	// unblock before exec, or the signal mask remains :(
	sigprocmask(SIG_SETMASK,&mask.original,NULL);
}

// wait and process signals
int waiter_wait(struct pollfd* poll,
								int npoll,
								const time_t timeoutsec) {
	static struct timespec timeout = {};
	timeout.tv_sec = timeoutsec;
	int res;
POLL_AGAIN:
	res = ppoll(poll,npoll,&timeout, &mask.nochild);
	if(res < 0) {
		switch(errno) {
		case EINTR:
			waiter_drain();
			return res;
		};
		error(0,errno,"waiter wait");
		abort();
	}
	return res;
}

// call this to drain a signalfd, and then waiter_next until it returns 0
void waiter_drain(void) {
	siginfo_t info;
	const static struct timespec poll = {0,0};
	for(;;) {
		int res = sigtimedwait(&mask.onlychild, &info, &poll);
		if(res < 0) {
			if(errno == EAGAIN) return;
			perror("drain");
			abort();
		}
		assert(res != 0);
		assert(res == sizeof(info));
		assert(info.si_signo == SIGCHLD);
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

bool waiter_waitfor(time_t sec, int expected, int *status) {
	//assert(child_processes == 1); as long as none of them die, processes are ok
	const struct timespec t = {
		sec, 0
	};
	siginfo_t info;
	int ret = sigtimedwait(&mask.onlychild, &info, &t);
	if(ret < 0) {
		// timed out
		if(errno == EAGAIN) return true;
	}
	waiter_drain();
	int test = waiter_next(status);
	if(test != expected) {
		// fail fast
		error(23,0,"wrong pid returned expected %d got %d",expected,test);
	}
	return false;
}

int waiter_processes(void) {
	return child_processes;
}
