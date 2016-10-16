all : tcp

tcp : main.c tcp3.c
	gcc -g -Wall -o $@ $^ 

clean :
	rm tcp