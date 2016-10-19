#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "tcp.h"

#define TCP_SEG_HEAD_SIZE 17

#define TCP_SEND_MEM 16384
#define TCP_RECV_MEM 16384

#define TCP_ACK_INTERVAL 200
#define TCP_FAST_RESEND_COUNT 3
#define TCP_MIN_SSTH 2

struct queue_node {
	struct queue_node* prev, *next;
};

struct tcp_segment
{
	struct queue_node node;
	int cmd;
	int num;
	int ts;
	int wnd;
	int ack_count;
	int rto;
	int resent_ts;
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
	struct queue_node snd_queue;
	struct queue_node rcv_queue;
	int cwnd;
	int ssth;
	int rwnd;
	int srtt;
	int rttvar;
	int rto;
	uint32_t ack_timer;
	char* ack_list;
	int ack_len;
	int ack_cap;
	uint32_t current;
	opfunc output_func;	
};

enum TCP_CMD {
	TCP_CMD_PUSH = 1,
	TCP_CMD_ACK,
};

#define member_offset(type, member) (uint64_t)&(((type*)0)->member)
#define infer_ptr(ptr, type, member) (type*)(((char*)(ptr)) - member_offset(type, member))

#define queue_init(queue, ptr) {(queue)->next = (queue)->prev = ptr;}
#define queue_is_empty(queue) ((queue)->next == (queue))
#define queue_entry(queue, type, member) infer_ptr((queue)->next, type, member)
#define queue_add_tail(queue, node) {\
	(node)->prev=(queue)->prev;\
	(queue)->prev->next=(node);\
	(node)->next=(queue);\
	(queue)->prev = (node);\
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

int imin(int a, int b)
{
	return a < b ? a : b;
}

int idiff(int a, int b)
{
	return a > b;
}

void write_segment(char* buff, struct tcp_segment* seg);

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
	queue_init(&t->snd_queue, &t->snd_queue);
	queue_init(&t->rcv_queue, &t->rcv_queue);
	t->cwnd = t->mss;
	t->ssth = TCP_RECV_MEM;
	t->rwnd = TCP_RECV_MEM;
	t->srtt = 0;
	t->rttvar = 0;
	t->rto = 1000;
	t->ack_timer = 0;
	t->ack_list = malloc(sizeof(uint32_t) * 2);
	t->ack_len = 0;
	t->ack_cap = 1;
	t->current = 0;

	return t;
}

void tcp_release(struct tcp_state* T)
{
	if (T) {
		if (T->ack_list) {
			free(T->ack_list);
			T->ack_list = NULL;
			T->ack_len = T->ack_cap = 0;
		}

		free(T);
		T = NULL;
	}
}

int byte_in_sending(struct tcp_state* T)
{
	if (queue_is_empty(&T->snd_queue))	
		return 0;

	struct tcp_segment* seg = queue_entry(&T->snd_queue, struct tcp_segment, node);
	return T->snd_next - seg->num;	
}

void flush_output(struct tcp_state* T, const char* buffer, int buf_len)
{
	T->output_func(buffer, buf_len);
}

int tcp_recv_wnd(struct tcp_state* T)
{
	return T->max_rcv - (T->rcv_next - T->rcv_head);
}

void tcp_update(struct tcp_state* T, uint32_t current)
{
	assert(T->output_func);

	int snd_len, buf_len, mwnd, i, change, lost;
	char buffer[2000];
	struct queue_node* node;
	struct tcp_segment ack_seg;

	change = 0;
	lost = 0;

	if (T->current > current) {
		return;
	}

	T->current = current;

	ack_seg.cmd = TCP_CMD_ACK;
	ack_seg.num = 0;
	ack_seg.ts  = 0;
	ack_seg.wnd = tcp_recv_wnd(T);
	ack_seg.ack_count = 0;
	ack_seg.len = 0;

	if (!T->ack_timer && T->ack_len > 0) {
		T->ack_timer = current;
	}

	// send data from snd_buffer
	mwnd = imin(T->cwnd, T->rwnd);
	snd_len = imin(mwnd - byte_in_sending(T), T->snd_tail - T->snd_next);

	buf_len = 0;
	if (T->ack_len > 0) {
		// send ack when timeout or can send data
		if (snd_len > 0 || idiff(current, T->ack_timer) > TCP_ACK_INTERVAL) {
			for (i = 0; i < T->ack_len; i++) {
				if (buf_len >= T->mss) {
					flush_output(T, buffer, buf_len);
					buf_len = 0;
				}

				uint32_t* ack_list = (uint32_t*)T->ack_list;
				ack_seg.num = ack_list[i * 2 + 0];
				ack_seg.ts  = ack_list[i * 2 + 1];

				write_segment(buffer + buf_len, &ack_seg);
				buf_len += TCP_SEG_HEAD_SIZE;
			}

			T->ack_len = 0;
		}
	} else {
		if (snd_len > 0) {
			ack_seg.num = T->rcv_next;
			ack_seg.ts  = 0;

			write_segment(buffer + buf_len, &ack_seg);
			buf_len += TCP_SEG_HEAD_SIZE;			
		}
	}

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
			s = segment_create(snd_len);
			len = snd_len;
		}

		memset(s, 0, sizeof(*s) + len);
		s->cmd = TCP_CMD_PUSH;
		s->num = T->snd_next;
		s->ts  = current;
		s->wnd = 0;
		s->ack_count = 0;
		s->rto = T->rto;
		s->resent_ts = T->current + s->rto;
		memcpy(s->data, T->snd_buffer + loop_offset(T->snd_next, TCP_SEND_MEM), len);
		s->len = len;

		write_segment(buffer + buf_len, s);
		queue_add_tail(&T->snd_queue, &s->node);

		buf_len += TCP_SEG_HEAD_SIZE + len;
		snd_len -= len;
		T->snd_next += len;
	}

	node = T->snd_queue.next;
	while (1) {
		if (node == &T->snd_queue) break;

		int need = 0;
		struct tcp_segment* seg = infer_ptr(node, struct tcp_segment, node);
		if (idiff(T->current, seg->resent_ts) > 0) {
			need = 1;
			seg->rto += T->rto;
			seg->resent_ts = T->current + seg->rto;
			lost++;
		} else if (seg->ack_count > TCP_FAST_RESEND_COUNT) {
			need = 1;
			seg->resent_ts = T->current + seg->rto;
			change++;
		}

		if (need) {
			seg->ts = T->current;
			seg->ack_count = 0;

			if (buf_len >= T->mss) {
				flush_output(T, buffer, buf_len);
				buf_len = 0;
			}

			write_segment(buffer + buf_len, seg);
			buf_len += TCP_SEG_HEAD_SIZE + seg->len;
		}

		node = node->next;
	}

	if (change) {
		T->ssth = T->cwnd / 2;
		T->cwnd = T->ssth + 3 * T->mss;
	}

	if (lost) {
		T->ssth = mwnd / 2;
		if (T->ssth < TCP_MIN_SSTH)
			T->ssth = TCP_MIN_SSTH;
		T->cwnd = T->mss;
	}

	if (buf_len > 0) {
		flush_output(T, buffer, buf_len);
		buf_len = 0;
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
	buf = write_uint32(buf, s->num);
	buf = write_uint32(buf, s->ts);
	buf = write_uint32(buf, s->wnd);
	buf = write_uint32(buf, s->len);
	buf = write_data(buf, s->data, s->len);
}

int tcp_send(struct tcp_state* T, const char* buffer, int len)
{
	if (len <= 0) return 0;
	assert(buffer);

	int wlen, clen;
	clen = T->max_snd - (T->snd_tail - T->snd_next);
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

const char* read_uint8(const char* buf, uint8_t* i)
{
	memcpy(i, buf, sizeof(uint8_t));
	buf += sizeof(uint8_t);
	return buf;
}

const char* read_uint32(const char* buf, uint32_t* i)
{
	memcpy(i, buf, sizeof(uint32_t));
	buf += sizeof(uint32_t);
	return buf;
}

const char* read_data(const char* buf, char* data, int len)
{
	memcpy(data, buf, len);
	buf += len;
	return buf;
}

struct tcp_segment* read_segment(const char* buf, int size)
{
	uint8_t cmd;
	uint32_t num, ts, wnd, len;
	struct tcp_segment* seg;

	buf = read_uint8(buf, &cmd);
	buf = read_uint32(buf, &num);
	buf = read_uint32(buf, &ts);
	buf = read_uint32(buf, &wnd);
	buf = read_uint32(buf, &len);
	if (TCP_SEG_HEAD_SIZE + len > size) {
		return NULL;
	}

	seg = segment_create(len);
	buf = read_data(buf, seg->data, len);

	seg->cmd = cmd;
	seg->num = num;
	seg->ts  = ts;
	seg->wnd = wnd;
	seg->len = len;
	return seg;
}

void update_ack_list(struct tcp_state* T, int num, uint32_t ts)
{
	if (T->ack_len >= T->ack_cap) {
		int ack_cap = T->ack_cap * 2;
		char* ack_list = malloc(sizeof(uint32_t) * 2 * ack_cap);
		memcpy(ack_list, T->ack_list, T->ack_cap);
		free(T->ack_list);
		T->ack_list = ack_list;
		T->ack_cap = ack_cap;
	}

	uint32_t* ack_list = (uint32_t*)T->ack_list;
	ack_list[2*T->ack_len + 0] = num;
	ack_list[2*T->ack_len + 1] = ts;
	T->ack_len++;
}

void recv_segment(struct tcp_state* T, struct tcp_segment* seg)
{
	struct queue_node* node;
	int flag, need_del, rcv_next, ts;

	flag = 0;
	need_del = 1;
	rcv_next = T->rcv_next;
	node = T->rcv_queue.next;

	if (seg->len > T->max_rcv - (T->rcv_next - T->rcv_head))
		return need_del;

	if (seg->num == rcv_next) 
		rcv_next += seg->len;

	while (1) {
		if (node == &T->rcv_queue)
			break;

		struct tcp_segment* cur = infer_ptr(node, struct tcp_segment, node);
		if (cur->num == rcv_next) 
			rcv_next += seg->len;

		if (!flag && seg->num < cur->num) {
			queue_insert(&T->rcv_queue, node, &seg->node);
			ts = seg->ts;
			flag = 1;
			need_del = 0;
		} 

		node = node->next;
	}

	if (node == &T->rcv_queue) {
		queue_add_tail(&T->rcv_queue, &seg->node);
		need_del = 0;
		ts = seg->ts;
	}

	T->rcv_next = rcv_next;

	update_ack_list(T, rcv_next, ts);

	return need_del;
}

void update_unack(struct tcp_state* T, int ack_next)
{
	struct tcp_segment* seg;
	while (1) {
		if (queue_is_empty(&T->snd_queue)) break;

		seg = queue_entry(&T->snd_queue, struct tcp_segment, node);

		if (seg->num >= ack_next)
			break;

		queue_delete(&T->snd_queue, &seg->node);
		segment_destroy(seg);
	}
}

void update_recv_buffer(struct tcp_state* T)
{
	struct queue_node* node;

	node = T->rcv_queue.next;
	while (1) {
		if (node == &T->rcv_queue)
			break;

		struct tcp_segment* seg = infer_ptr(node, struct tcp_segment, node);
		if (seg->num >= T->rcv_next) 
			break;

		assert(seg->len < T->max_rcv - (T->rcv_next - T->rcv_head));
		memcpy(T->rcv_buffer + loop_offset(T->rcv_next, TCP_RECV_MEM), seg->data, seg->len);

		queue_delete(&T->rcv_queue, &seg->node);
		segment_destroy(seg);

		node = node->next;
	}
}

void update_rtt(struct tcp_state* T, int rtt)
{
	float alpha, beta;

	alpha = 0.125f;// 1/8;
	beta = 0.25f;// 1/4;

	if (T->srtt == 0) {
		T->srtt = rtt;
		T->rttvar = rtt/2;
	} else {
		T->srtt = (1 - alpha) * T->srtt + alpha * rtt;
		// RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
		T->rttvar = (1 - beta) * T->rttvar + beta * (T->srtt > rtt ? (T->srtt - rtt):(rtt - T->srtt)); 
	}
}

int tcp_input(struct tcp_state* T, const char* buffer, int len)
{
	if (len <= 0) return -1;

	int del;
	struct tcp_segment* seg;
	struct queue_node* node;

	del = 0;

	while (1) {
		if (len < TCP_SEG_HEAD_SIZE)
			break;

		seg = read_segment(buffer, len);
		if (seg == NULL)
			break;

		if (TCP_CMD_PUSH == seg->cmd) {
			if (seg->num >= T->rcv_next) 
				del = recv_segment(T, seg);
			else 
				del = 1;
		} 

		if (TCP_CMD_ACK == seg->cmd) {
			T->rwnd = seg->wnd;

			node = T->snd_queue.next;
			while (1) {
				if (node == &T->snd_queue) break;

				struct tcp_segment* s = infer_ptr(node, struct tcp_segment, node);
				if (s->num + s->len == seg->num && s->ts == seg->ts) {
					int rtt = T->current - s->ts;
					update_rtt(T, rtt);
					break;
				}

				if (s->num == seg->num && s->ts >= seg->ts) {
					s->ack_count++;
					break;
				}

				node = node->next;
			}

			update_unack(T, seg->num);
		}

		len -= TCP_SEG_HEAD_SIZE + seg->len;

		if (del) segment_destroy(seg);
	}

	update_recv_buffer(T);

	return 0;
}

void tcp_regoutput(struct tcp_state* T, opfunc func)
{
	T->output_func = func;
}