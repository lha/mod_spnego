
KRB5_CONFIG=krb5-config

UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
  ARCHS=i386 x86_64

  SDKPATH=$(shell xcrun --show-sdk-path)

  CFLAGS = -Wc,-g $(foreach arch,$(ARCHS),"-Wc,-arch $(arch)")
  LDFLAGS = -Wl,-g $(foreach arch,$(ARCHS),"-Wl,-arch $(arch)") -Wl,-framework,GSS
  KRB5=-DHAVE_GSS_FRAMEWORK -DHAVE_HEIMDAL

  CFLAGS += -I$(SDKPATH)/usr/include/apr-1
  CFLAGS += -I$(SDKPATH)/usr/include/apache2
  CFLAGS += "-Wc,-isystem $(SDKPATH)/usr/include"
  CFLAGS += "-Wc,-F$(SDKPATH)/System/Library/Frameworks"

  LDFLAGS += "-Wl,-F$(SDKPATH)/System/Library/Frameworks"

else
  CFLAGS = -Wc,-g
  LDFLAGS = -Wl,-g
  CPPFLAGS= `krb5-config --cflags gssapi krb5`
  LIBS= `krb5-config --libs gssapi krb5`
  KRB5=-DHAVE_KRB5
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
