#CPPFLAGS= -Wc,-F/System/Library/PrivateFrameworks
#LIBS= -Wl,-F/System/Library/PrivateFrameworks -framework Heimdal
#KRB5=-DHAVE_KRB5 -DHAVE_HEIMDAL

CPPFLAGS= `krb5-config --cflags gssapi`
LIBS= `krb5-config --libs gssapi`
KRB5=-DHAVE_KRB5

ARCHS=i386 x86_64

UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
  CFLAGS = -Wc,-g $(foreach arch,$(ARCHS),"-Wc,-arch $(arch)")
  LDFLAGS = -Wl,-g $(foreach arch,$(ARCHS),"-Wl,-arch $(arch)")
else
  CFLAGS = -Wc,-g
  LDFLAGS = -Wl,-g
endif

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
