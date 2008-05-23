# $Id: Makefile 3399 2004-04-05 20:21:52Z lha $

CPPFLAGS= `krb5-config --cflags gssapi`
LIBS= `krb5-config --libs gssapi`
KRB5=-DHAVE_KRB5

CFLAGS = -g

APXS = apxs

SRCS = mod_spnego.c

all: mod_spnego.la

mod_spnego.la: $(SRCS)
	$(APXS) -o $@ -c $(CPPFLAGS) $(KRB5) $(SRCS) $(LIBS)

install:
	$(APXS) -i mod_spnego.so

clean:
	rm -f mod_spnego.so *.o *~ core *.core *.slo *.lo *.la
