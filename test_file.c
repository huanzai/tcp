#include "tcp.h"
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

struct tunnel;

struct tcp_state* T1;
struct tcp_state* T2;
struct tunnel* tun;

char* start_buf;
char* send_buf;
int total_send;
int total_recv;

struct queue_node {
	struct queue_node *prev, *next;
	int len;
	char data[1];
};

struct tunnel {
	struct queue_node in1_2;
	struct queue_node in2_1;
	struct queue_node out1_2;
	struct queue_node out2_1;
};

struct queue_node* create_qnode(int len)
{
	return malloc(sizeof(struct queue_node) + len);
}

#define queue_init(queue, ptr) ((queue)->prev = (queue)->next = ptr)

#define queue_is_empty(queue) ((queue)->next == queue)

#define queue_add(queue, node) {\
	(node)->prev=(queue)->prev;\
	(queue)->prev->next=(node);\
	(node)->next=(queue);\
	(queue)->prev = (node);\
}

#define queue_del(node) {\
	(node)->prev->next = (node)->next;\
	(node)->next->prev = (node)->prev;\
}

#define queue_entry(queue) ((queue)->next)

uint32_t iclock() 
{
	uint32_t value;
	uint64_t sec, usec;
	struct timeval time;
	gettimeofday(&time, NULL);
	sec = time.tv_sec;
	usec = time.tv_usec;

	value = (uint32_t)((sec * 1000 + usec / 1000) % 0x7fffffff);
	return value;
}

void isleep(uint64_t millisecond)
{
	usleep((millisecond << 10) - (millisecond << 4) - (millisecond << 3));
}

struct tunnel* tunnel_create()
{
	struct tunnel* t = malloc(sizeof(*t));
	queue_init(&t->in1_2, &t->in1_2);
	queue_init(&t->in2_1, &t->in2_1);
	queue_init(&t->out1_2, &t->out1_2);
	queue_init(&t->out2_1, &t->out2_1);
	
	return t;
}

void tunnel_update(struct tunnel* t, uint32_t current)
{
	while(1) {
		if (queue_is_empty(&t->in1_2))
			break;

		struct queue_node* node = queue_entry(&t->in1_2);
		queue_del(node);

		queue_add(&t->out1_2, node);
	}

	while(1) {
		if (queue_is_empty(&t->in2_1))
			break;

		struct queue_node* node = queue_entry(&t->in2_1);
		queue_del(node);

		queue_add(&t->out2_1, node);
	}
}

int output1_2(const char* buf, int len)
{
	struct queue_node* node;

	node = create_qnode(len);
	node->len = len;
	memcpy(node->data, buf, len);

	queue_add(&tun->in1_2, node);
	return 0;
}

int output2_1(const char* buf, int len)
{
	struct queue_node* node;

	node = create_qnode(len);
	node->len = len;
	memcpy(node->data, buf, len);

	queue_add(&tun->in2_1, node);
	return 0;
}

char *read_file(const char* file, int* len)
{
	FILE *f = fopen(file, "rb");
	if (!f) {
		return NULL;
	}

	char *buf;
	fseek(f, 0, SEEK_END);
	*len = ftell(f);
	buf = malloc(*len + 1);
	rewind(f);
	fread(buf, 1, *len, f);
	buf[*len] = '\0';
	fclose(f);
	return buf;
}

void append_file(const char* file, const char* buf)
{
	FILE* f = fopen(file, "ab");
	if (!f) {
		return;
	}

	fprintf(f, "%s", buf);
	fclose(f);
}

void update(uint32_t current)
{
	char buf[2000];
	int can_send;
	int recv_count;

	tunnel_update(tun, current);
	tcp_update(T1, current);
	tcp_update(T2, current);

	while (!queue_is_empty(&tun->out1_2)) {
		struct queue_node* node = queue_entry(&tun->out1_2);
		queue_del(node);
		tcp_input(T2, node->data, node->len);
	}

	while (!queue_is_empty(&tun->out2_1)) {
		struct queue_node* node = queue_entry(&tun->out2_1);
		queue_del(node);

		tcp_input(T1, node->data, node->len);
	}

	can_send = total_send - (send_buf - start_buf);
	if (can_send > 0) {
		int count = tcp_send(T1, send_buf, can_send);
		send_buf += count;

		if (count > 0) {
			printf("==============>>> send:%d\n", (int)(send_buf - start_buf));
		}
	}

	if ((recv_count = tcp_recv(T2, buf, 1999))) {
		printf("==============>>> recv:%d\n", total_recv + recv_count);

		buf[recv_count] = '\0';
		append_file("rfc793_2.txt", buf);
		total_recv += recv_count;
	}
}

void test()
{
	T1 = tcp_create(1001);
	T2 = tcp_create(1002);

	tcp_regoutput(T1, output1_2);
	tcp_regoutput(T2, output2_1);

	tun = tunnel_create();

	const char* rfile = "rfc793.txt";
	start_buf = read_file(rfile, &total_send);
	if (!start_buf) {
		printf("can't open file %s", rfile);
		return;
	}
	send_buf = start_buf;

	while (total_recv < total_send) {
		isleep(1);
		update(iclock());
	}

	free(start_buf);
}