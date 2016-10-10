#include "tcp.h"
#include <string.h>
#include <stdint.h>

#define TCP_SEG_HEAD_SIZE 9;

struct tcp_state {
	int mtu;
	int mss;
	int snd_next;
	int rcv_next;
	struct queue_node* snd_buffer;
	struct queue_node* rcv_queue;
	opfunc output_func;	
};

struct queue_node {
	struct queue_node* prev, next;
};

struct tcp_segment
{
	struct queue_node* node;
	int cmd;
	int number;
	int snd_stamp;
	int req_times;
	int len;
	char data[0];
};

enum TCP_CMD {
	TCP_CMD_PUSH = 1,
	TCP_CMD_ACK,
};

#define member_offset(type, member) (uint32_t)&(((type*)0)->member)

#define queue_init(queue, ptr) {queue->next = queue->prev = ptr;}
#define queue_is_empty(queue) ((queue)->next == (queue))
#define queue_entry(queue, type, member) (type*)((char*)((queue)->next) - member_offset(type, member)) 
#define queue_add_tail(queue, node) {\
	(node)->prev=(queue)->prev;\
	(queue)->prev->next=(node);\
	(node)->next=(queue);\
}
#define queue_insert(queue, cur_node, new_node) {\
	(new_node)->prev = (cur_node)->prev;\
	(new_node)->prev->next = (new_node);\
	(new_node)->next = (cur_node);\
	(cur_node)->prev = (new_node);\
}
#define queue_delete(queue, node) {\
	(node)->prev->next = (node)->next; \
	(node)->next->prev = (node)->prev; \
}

struct tcp_state* tcp_create() 
{
	struct tcp_state* t = malloc(sizeof(struct tcp_state));
	memset(t, 0, sizeof(*t));

	t->mtu = 1400;
	t->mss = t->mtu - TCP_SEG_HEAD_SIZE;
	t->snd_next = 0;
	t->rcv_next = 0;
	queue_init(t->snd_buffer, &t->snd_buffer);
	queue_init(t->rcv_queue, &t->rcv_queue);

	return t;
}

void tcp_release(struct tcp_state* T)
{
	if (T) {
		free(T);
	}
}

void tcp_update(struct tcp_state* T, uint32_t current)
{

}

struct tcp_segment create_segment(struct tcp_state* T, int size)
{
	struct tcp_segment* seg = malloc(sizeof(struct tcp_segment) + size);
	return seg;
}

char* write_uint8(char* buf, uint8_t i)
{
	memcpy(buf, &i, sizeof(uint8_t));
	buf += sizeof(uint8_t);
	return buf;
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
	buf = write_uint8(buf, s->cmd);
	buf = write_uint32(buf, s->number);
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

		s->cmd = TCP_CMD_PUSH;
		s->number = T->snd_next++;

		// send data
		char buf[2000];
		write_segment(buf, s);
		T->output_func(buf, s->len + TCP_SEG_HEAD_SIZE);

		queue_add_tail(T->snd_buffer, s);

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
		if (queue_is_empty(T->rcv_queue)) break;

		struct tcp_segment* seg = queue_entry(T->rcv_queue, struct tcp_segment, node);
		if (seg->len + count > len) {
			return count;
		}

		memcpy(ptr, seg->data, seg->len);
		ptr += seg->len;
		count += seg->len;
	}
	return count;
}

char* read_uint8(char* buf, uint8_t* i)
{
	memcpy(i, buf, sizeof(uint8_t));
	buf += sizeof(uint8_t);
	return buf;
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

struct tcp_segment* read_segment(char* buf, int size)
{
	uint8_t cmd;
	uint32_t number,len;
	struct tcp_segment* seg;

	buf = read_uint8(buf, &cmd);
	buf = read_uint32(buf, &number);
	buf = read_uint32(buf, &len);
	if (TCP_SEG_HEAD_SIZE + len > size) {
		return NULL;
	}

	seg = malloc(sizeof(*seg)+len);
	buf = read_data(buf, seg->data, len);

	seg->cmd = cmd;
	seg->number = number;
	seg->len = len;
	return seg;
}

void recv_segment(struct tcp_state* T, struct tcp_segment* seg)
{
	struct queue_node* node;
	int flag, rcv_next;

	flag = 0;
	rcv_next = T->rcv_next;
	node = T->rcv_queue->next;

	if (seg->number == rcv_next) {
		rcv_next ++;
	}

	while (1) {
		if (node == T->rcv_queue) {
			break;
		}

		if (node->number == rcv_next) {
			rcv_next ++;
		}

		if (!flag && seg->number < node->number) {
			queue_insert(T->rcv_queue, node, seg->node);
			flag = 1;
		} 

		node = node->next;
	}

	if (node == T->rcv_queue) {
		queue_add_tail(T->rcv_queue, seg->node);
	}

	T->rcv_next = rcv_next;
}

void update_unack(struct tcp_state* T, int ack_next)
{
	while (1) {
		if (queue_is_empty(T->snd_buffer)) break;
		struct tcp_segment* seg = queue_entry(T->snd_buffer, struct tcp_segment, node);

		if (seg->number < ack_next) {
			queue_delete(T->snd_buffer, seg->node);
		} else {
			break;
		}
	}
}

int tcp_input(struct tcp_state* T, const char* buffer, int len)
{
	if (len <= 0) return -1;

	int ack_next = 0;
	struct tcp_segment ack_seg, *seg;

	while (1) {
		if (len < TCP_SEG_HEAD_SIZE) {
			break;
		}

		seg = read_segment(buffer, len);
		if (seg == NULL) {
			break;
		}

		if (seg->cmd == TCP_CMD_PUSH) {
			if (seg->number >= T->rcv_next) {
				recv_segment(T, seg);
			}
		} else if (seg->cmd == TCP_CMD_ACK) {
			if (ack_next < seg->number) 
				ack_next = seg->number;
		}

		len -= TCP_SEG_HEAD_SIZE + seg->len;
	}

	update_unack(T, ack_next);

	if (!queue_is_empty(T->snd_buffer)) {
		seg = queue_entry(T->snd_buffer, struct tcp_segment, node);
		if (seg->number == ack_next) {
			seg->req_times ++;	
		}
	}

	ack_seg.cmd = TCP_CMD_ACK;
	ack_seg.number = T->rcv_next;

	// send data
	char buf[2000];
	write_segment(buf, ack_seg);
	T->output_func(buf, ack_seg.len + TCP_SEG_HEAD_SIZE);

	return 0;
}

int tcp_regoutput(struct tcp_state* T, opfunc func)
{
	T->output_func = func;
}