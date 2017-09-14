CFLAGS+=-ggdb
LDFLAGS += -lssh
O=$(foreach name,$(N),$(info "-include d/$(name)") $(name).o)
LINK=$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
N=main waiter sshutil note

all: main test_sshutil
main: $(O)
	$(LINK)

N=test_sshutil sshutil  note
test_sshutil: $(O)
