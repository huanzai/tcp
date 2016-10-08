#include "tcp.h"
#include <string.h>
#include <stdint.h>

#define TCP_SEG_HEAD_SIZE 4;

struct tcp_state {
	int mtu;
	int mss;
	struct queue_node* recv_queue;
	opfunc output_func;	
};

struct queue_node {
	struct queue_node* prev, next;
};

struct tcp_segment
{
	struct queue_node* node;
	int len;
	char data[0];
};

#define member_offset(type, member) (uint32_t)&(((type*)0)->member)

#define queue_init(queue, ptr) {queue->next = queue->prev = ptr;}
#define queue_is_empty(queue) ((queue)->next == (queue))
#define queue_entry(queue) (struct tcp_segment*)((char*)((queue)->next) - member_offset(struct tcp_segment, node)) 
#define queue_add_tail(queue, seg) {(seg)->node->prev=(queue)->prev;(queue)->prev->next=(seg)->node;(seg)->node->next=(queue);}

struct tcp_state* tcp_create() 
{
	struct tcp_state* t = malloc(sizeof(struct tcp_state));
	memset(t, 0, sizeof(*t));

	t->mtu = 1400;
	t->mss = t->mtu - TCP_SEG_HEAD_SIZE;

	return t;
}

void tcp_release(struct tcp_state* T)
{
	if (T) {
		free(T);
	}
}

struct tcp_segment create_segment(struct tcp_state* T, int size)
{
	struct tcp_segment* seg = malloc(sizeof(struct tcp_segment) + size);
	return seg;
}

char* write_uint32(char* buf, uint32_t i)
{
	memcpy(buf, &i, sizeof(uint32_t));
	buf += sizeof(uint32_t);
	return buf;
}

char* write_data(char* buf, const char* d, int len)
{
	memcpy(buf, d, len);
	buf += len;
	return buf;
}

void write_segment(char* buf, struct tcp_segment* s)
{
	buf = write_uint32(buf, s->len);
	buf = write_data(buf, s->data, s->len);
}

int tcp_send(struct tcp_state* T, const char* buffer, int len)
{
	if (len <= 0) return -1;

	while (1) {
		struct tcp_segment* s;
		int size;
		if (T->mss < len) {
			s = create_segment(T, T->mss);
			size = T->mss;
		} else {
			s = create_segment(T, len);
			size = len;
		}

		memcpy(s->data, buffer, size);
		s->len = size;
		len -= size;

		// send data
		char buf[2000];
		write_segment(buf, s);
		T->output_func(buf, s->len + TCP_SEG_HEAD_SIZE);

		if (len == 0) {
			break;
		}
	}

	return 0;
}

int tcp_recv(struct tcp_state* T, char* buffer, int len)
{
	int count = 0;
	char* ptr = buffer;
	while(1) {
		if (queue_is_empty(T->recv_queue)) break;

		struct tcp_segment* seg = queue_entry(T->recv_queue);
		if (seg->len + count > len) {
			return count;
		}

		memcpy(ptr, seg->data, seg->len);
		ptr += seg->len;
		count += seg->len;
	}
	return count;
}

char* read_uint32(char* buf, uint32_t* i)
{
	memcpy(i, buf, sizeof(uint32_t));
	buf += sizeof(uint32_t);
	return buf;
}

char* read_data(char* buf, char* data, int len)
{
	memcpy(data, buf, len);
	buf += len;
	return buf;
}

struct tcp_segment* read_segment(char* buf)
{
	int len;
	buf = read_uint32(buf, &len);
	struct tcp_segment* seg = malloc(sizeof(*seg)+len);
	seg->len = len;
	buf = read_data(buf, seg->data, len);
	return seg;
}

int tcp_input(struct tcp_state* T, const char* buffer, int len)
{
	if (len <= 0) return -1;

	struct tcp_segment* seg = read_segment(buffer);

	queue_add_tail(T->recv_queue, seg);

	return 0;
}

int tcp_regoutput(struct tcp_state* T, opfunc func)
{
	T->output_func = func;
}