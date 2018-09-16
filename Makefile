CFLAGS+=-ggdb -fPIC
LIBTOOL=libtool --mode=$1 --tag=CC

LINK=$(call LIBTOOL,link) $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
COMPILE=$(call LIBTOOL,compile) $(CC) $(CFLAGS) -c -o $@ $<

O=$(foreach name,$(N),$(eval include d/$(name)) $(name).o)

all: libwaiter.la

N=waiter
libwaiter.la: $(O)
	$(LINK)

d/%: %.c | d
	$(CC) $(CFLAGS) -MM -MG -o $@ $<

o/%.o: %.c

d:
	mkdir $@
