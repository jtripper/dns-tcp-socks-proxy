.PHONY : all clean

CFLAGS ?= -Wall -Wextra

daemon_name = dns_proxy

all: $(daemon_name)

$(daemon_name): $(daemon_name).c

clean :
	-rm -f $(daemon_name)

