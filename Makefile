
libtun_alloc.so: tun_alloc.c
	gcc -Wall -fPIC -c tun_alloc.c -o tun_alloc.o
	gcc -shared -o libtun_alloc.so tun_alloc.o
	rm tun_alloc.o

all: libtun_alloc.so

