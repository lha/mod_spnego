# $Id: Makefile 3399 2004-04-05 20:21:52Z lha $

CPPFLAGS= -Wc,-F/System/Library/PrivateFrameworks
LIBS= -Wl,-F/System/Library/PrivateFrameworks -framework Heimdal
KRB5=-DHAVE_KRB5 -DHEIMDAL_FRAMEWORK

#CPPFLAGS= `krb5-config --cflags gssapi`
#LIBS= `krb5-config --libs gssapi`
#KRB5=-DHAVE_KRB5

ARCHS=i386 x86_64

CFLAGS = -Wc,-g $(foreach arch,$(ARCHS),"-Wc,-arch $(arch)")
LDFLAGS = -Wl,-g $(foreach arch,$(ARCHS),"-Wl,-arch $(arch)")

APXS = apxs

SRCS = mod_spnego.c

all: mod_spnego.la

mod_spnego.la: $(SRCS)
	$(APXS) -o $@ -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(KRB5) $(SRCS) $(LIBS)

install: mod_spnego.la
	$(APXS) -i mod_spnego.la

clean:
	rm -f mod_spnego.so *.o *~ core *.core *.slo *.lo *.la
	rm -rf .libs