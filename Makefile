CFLAGS+=-ggdb -fPIC
O=$(foreach name,$(N),$(eval include d/$(name)) $(name).o)
LINK=$(CC) -shared $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

N=waiter
libwaiter.a: $(O)
	$(LINK)

d/%: %.c | d
	$(CC) $(CFLAGS) -MM -MG -o $@ $<

d:
	mkdir $@
