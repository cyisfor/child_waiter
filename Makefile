CFLAGS+=-ggdb
LDFLAGS += -lssh
all: main test_sshutil
O=$(foreach $(N),name,$(eval "-include d/$(name)")$(n).o)

N=main waiter sshutil note
main: $(O)

N=test_sshutil sshutil  note
test_sshutil: $(O)
