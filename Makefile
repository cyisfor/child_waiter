CFLAGS+=-ggdb
LDFLAGS += -lssh
O=$(foreach name,$(N),$(eval include d/$(name)) $(name).o)
LINK=$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
N=main waiter sshutil note

all: main test_sshutil
main: $(O)
	$(LINK)

N=test_sshutil sshutil note waiter
test_sshutil: $(O)

d/%: %.c | d
	$(CC) $(CFLAGS) -MM -MG -o $@ $<

d:
	mkdir $@
