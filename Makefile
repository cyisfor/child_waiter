CFLAGS+=-ggdb
LDFLAGS += -lssh
all: main test_sshutil
main: main.o waiter.o  sshutil.o note.o

test_sshutil: test_sshutil.o sshutil.o  note.o
