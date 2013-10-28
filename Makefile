FLAGS=-Wall
all:
	gcc $(FLAGS) -o dns_proxy dns_proxy.c -g -lev
.PHONY : clean
clean :
	-rm dns_proxy

