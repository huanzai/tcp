all : tcp

tcp : main.c tcp.c
	gcc -g -Wall -o $@ $^ 

clean :
	rm tcp
