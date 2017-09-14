CFLAGS+=-ggdb
LDFLAGS += -lssh
all: main test_sshutil
O=$(foreach name,$(N),$(message "-include d/$(name)") $(n).o)
LINK=$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
N=main waiter sshutil note
main: $(O)
	$(LINK)

N=test_sshutil sshutil  note
test_sshutil: $(O)
