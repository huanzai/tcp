#include "tcp.h"
#include <string.h>
#include <stdint.h>

#define TCP_SEG_HEAD_SIZE 9;

#define TCP_SEND_MEM 16384
#define TCP_RECV_MEM 16384

#define TCP_ACK_INTERVAL 200

struct queue_node {
	struct queue_node* prev, next;
};

struct tcp_segment
{
	struct queue_node* node;
	int cmd;
	int snd_number;
	int ack_number;
	int timestamp;
	int req_times;
	int len;
	char data[0];
};

struct tcp_state {
	int mtu;
	int mss;
	char snd_buffer[TCP_SEND_MEM];
	char rcv_buffer[TCP_RECV_MEM];
	int max_snd;
	int max_rcv;
	int snd_next;
	int snd_tail;
	int rcv_next;
	int rcv_head;
	int has_ack;
	int has_beack;
	struct queue_node* snd_queue;
	struct queue_node* rcv_queue;
	int cwnd;
	int ssth;
	int rwnd;
	int srtt;
	int rttvar;
	int rto;
	uint32_t ack_timer;
	opfunc output_func;	
};

enum TCP_CMD {
	TCP_CMD_PUSH = 1 << 0,
	TCP_CMD_ACK  = 1 << 1,
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

#define loop_offset(cur, max) ((cur) % (max))

#define segment_create(len) malloc(sizeof(struct tcp_segment) + (len))
#define segment_destroy(seg) {\
	free(seg);\
	seg = NULL;\
}

int idiff(int a, int b)
{
	return a > b;
}

struct tcp_state* tcp_create() 
{
	struct tcp_state* t = malloc(sizeof(struct tcp_state));
	memset(t, 0, sizeof(*t));

	t->mtu = 1400;
	t->mss = t->mtu - TCP_SEG_HEAD_SIZE;
	t->max_snd = TCP_SEND_MEM;
	t->max_rcv = TCP_RECV_MEM;
	t->snd_next = 0;
	t->snd_tail = 0;
	t->rcv_next = 0;
	t->rcv_head = 0;
	t->has_ack = 0;
	queue_init(t->snd_queue, &t->snd_queue);
	queue_init(t->rcv_queue, &t->rcv_queue);
	t->cwnd = T->mss;
	t->ssth = TCP_RECV_MEM;
	t->rwnd = TCP_RECV_MEM;
	t->srtt = 0;
	t->rttvar = 0;
	t->rto = 1000;

	return t;
}

void tcp_release(struct tcp_state* T)
{
	if (T) {
		free(T);
		T = NULL;
	}
}

int byte_in_sending(struct tcp_state* T)
{
	if (queue_is_empty(T->snd_queue))	
		return 0;

	struct tcp_segment* seg = queue_entry(T->snd_queue, struct tcp_segment, node);
	return T->snd_next - seg->snd_number;	
}

void flush_output(struct tcp_state* T, const char* buffer, int buf_len)
{
	T->output_func(buffer, buf_len);
}

void tcp_update(struct tcp_state* T, uint32_t current)
{
	int snd_len, buf_len, mwnd;
	char buffer[2000];
	struct tcp_segment ack_seg;

	memset(&ack_seg, 0, sizeof(struct tcp_segment));

	if (!T->ack_timer && T->has_ack != T->rcv_next) {
		T->ack_timer = current;
	}

	// send data from snd_buffer
	mwnd = imin(T->cwnd, T->rwnd);
	snd_len = imin(mwnd - byte_in_sending(T), T->snd_tail - T->snd_next);

	buf_len = 0;
	while (1) {
		if (snd_len == 0)
			break;

		if (buf_len >= T->mss) {
			flush_output(T, buffer, buf_len);
			buf_len = 0;
		}

		struct tcp_segment* s;
		int len;
		if (T->mss < snd_len) {
			s = segment_create(T->mss);
			len = T->mss;
		} else {
			s = segment_create(len);
			len = snd_len;
		}

		memset(s, 0, sizeof(*s) + len);
		s->cmd = TCP_CMD_PUSH | TCP_CMD_ACK;
		s->snd_number = T->snd_next;
		s->ack_number = T->rcv_next;
		s->timestamp = current;
		s->req_times = 0;
		memcpy(s->data, T->snd_buffer + loop_offset(T->snd_next, TCP_SEND_MEM));
		s->len = len;

		write_segment(buffer + buf_len, s);
		queue_add_tail(T->snd_queue, s);

		buf_len += len;
		snd_len -= len;
		T->snd_next += len;

		T->has_ack = T->rcv_next;
		T->ack_timer = 0;
	}

	if (buf_len > 0) {
		flush_output(T, buffer, buf_len);
		buf_len = 0;
	}

	// send ack segment when timeout 
	if (T->has_ack != T->rcv_next && idiff(current, T->ack_timer) > TCP_ACK_INTERVAL) {
		ack_seg.cmd = TCP_CMD_ACK;
		ack_seg.ack_number = T->rcv_next;

		write_segment(buffer, &ack_seg);
		flush_output(T, buffer, TCP_SEG_HEAD_SIZE);
	}
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
	buf = write_uint32(buf, s->snd_number);
	buf = write_uint32(buf, s->ack_number);
	buf = write_uint32(buf, s->timestamp);
	buf = write_uint32(buf, s->len);
	buf = write_data(buf, s->data, s->len);
}

int imin(int a, int b)
{
	return a < b ? a : b;
}

int tcp_send(struct tcp_state* T, const char* buffer, int len)
{
	if (len <= 0) return 0;
	assert(buffer);

	int wlen, clen;
	clen = T->max_snd - (T->snd_tail - T->snd_next)
	wlen = imin(clen, len);

	memcpy(T->snd_buffer + loop_offset(T->snd_tail, TCP_SEND_MEM), buffer, wlen);
	T->snd_tail += wlen;

	return wlen;
}

int tcp_recv(struct tcp_state* T, char* buffer, int len)
{
	if (len <= 0) return 0;

	int wlen, clen;
	clen = T->rcv_next - T->rcv_head;
	wlen = imin(clen, len);

	memcpy(buffer, T->rcv_buffer + loop_offset(T->rcv_head, TCP_RECV_MEM), wlen);
	T->rcv_head += wlen;

	return wlen;
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
	uint32_t snd_number, ack_number, timestamp,len;
	struct tcp_segment* seg;

	buf = read_uint8(buf, &cmd);
	buf = read_uint32(buf, &snd_number);
	buf = read_uint32(buf, &ack_number);
	buf = read_uint32(buf, &timestamp);
	buf = read_uint32(buf, &len);
	if (TCP_SEG_HEAD_SIZE + len > size) {
		return NULL;
	}

	seg = segment_create(len);
	buf = read_data(buf, seg->data, len);

	seg->cmd = cmd;
	seg->snd_number = snd_number;
	seg->ack_number = ack_number;
	seg->timestamp = timestamp;
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

	if (seg->len > T->max_rcv - (T->rcv_next - T->rcv_head))
		return;

	if (seg->snd_number == rcv_next) 
		rcv_next += seg->len;

	while (1) {
		if (node == T->rcv_queue)
			break;

		struct tcp_segment* cur = queue_entry(T->rcv_queue, struct tcp_segment, node);
		if (cur->snd_number == rcv_next) 
			rcv_next += seg->len;

		if (!flag && seg->snd_number < cur->snd_number) {
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
		if (queue_is_empty(T->snd_queue)) break;
		struct tcp_segment* seg = queue_entry(T->snd_queue, struct tcp_segment, node);

		if (seg->snd_number >= ack_next)
			break;

		queue_delete(T->snd_queue, seg->node);
		segment_destroy(seg);
		flag = 1;
	}
}

void update_recv_buffer(struct tcp_state* T)
{
	struct queue_node* node;
	node = T->rcv_queue->next;

	while (1) {
		if (node == T->rcv_queue)
			break;

		struct tcp_segment* seg = queue_entry(T->snd_queue, struct tcp_segment, node);
		if (seg->snd_number >= T->rcv_next) 
			break;

		assert(seg->len < T->max_rcv - (T->rcv_next - T->rcv_head));
		memcpy(T->rcv_buffer + loop_offset(T->rcv_next, TCP_RECV_MEM), seg->data, seg->len);

		queue_delete(T->rcv_queue, seg->node);
		segment_destroy(seg);

		node = node->next;
	}
}

int tcp_input(struct tcp_state* T, const char* buffer, int len)
{
	if (len <= 0) return -1;

	int has_beack;
	struct tcp_segment* seg;
	char buffer[2000];

	has_beack = 0;

	while (1) {
		if (len < TCP_SEG_HEAD_SIZE)
			break;

		seg = read_segment(buffer, len);
		if (seg == NULL)
			break;

		if (seg->cmd & TCP_CMD_PUSH) {
			if (seg->snd_number >= T->rcv_next) {
				recv_segment(T, seg);
			}
		} 
		if (seg->cmd & TCP_CMD_ACK) {
			if (has_beack < seg->ack_number)
				has_beack = seg->ack_number;
		}

		len -= TCP_SEG_HEAD_SIZE + seg->len;
	}

	update_unack(T, ack_next);

	if (!queue_is_empty(T->snd_queue)) {
		seg = queue_entry(T->snd_queue, struct tcp_segment, node);
		if (seg->snd_number == ack_next) {
			seg->req_times ++;	
		}
	}

	update_recv_buffer(T);

	return 0;
}

int tcp_regoutput(struct tcp_state* T, opfunc func)
{
	T->output_func = func;
}