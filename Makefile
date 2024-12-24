ryu: ryu.c
	gcc -o ryu ryu.c -O3 -Wall -Werror -pthread -lz

run: 
	./ryu --directory hello
