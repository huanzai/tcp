#ifndef _TCP_H_
#define _TCP_H_

#include <stdint.h>

struct tcp_state;

typedef int (*opfunc)(const char*, int);

struct tcp_state* tcp_create();
void tcp_release(struct tcp_state* T);

void tcp_update(struct tcp_state* T, uint32_t current);

int tcp_send(struct tcp_state* T, const char* buffer, int len);
int tcp_recv(struct tcp_state* T, char* buffer, int len);

int tcp_input(struct tcp_state* T, const char* buffer, int len);
void tcp_regoutput(struct tcp_state* T, opfunc func);

#endif