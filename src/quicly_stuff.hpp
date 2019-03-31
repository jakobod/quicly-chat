//
// Created by boss on 31.03.19.
//

#ifndef PICOQUIC_TEST_QUICLY_STUFF_HPP
#define PICOQUIC_TEST_QUICLY_STUFF_HPP

extern "C" {
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "../picotls/t/util.h"
}

int client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
int parse_request(ptls_iovec_t input, ptls_iovec_t *path, int *is_http1);
int path_is(ptls_iovec_t path, const char *expected);
void send_str(quicly_stream_t *stream, const char *s);
void send_header(quicly_stream_t *stream, int is_http1, int status, const char *mime_type);
int send_file(quicly_stream_t *stream, int is_http1, const char *fn, const char *mime_type);
int send_sized_text(quicly_stream_t *stream, ptls_iovec_t path, int is_http1);
int on_stop_sending(quicly_stream_t *stream, int err);
int on_receive_reset(quicly_stream_t *stream, int err);
int server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
int server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
int client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
void on_closed_by_peer(quicly_closed_by_peer_t *self, quicly_conn_t *conn,
                       int err, uint64_t frame_type, const char *reason,
                              size_t reason_len);
int send_one(int fd, quicly_datagram_t *p);
int send_pending(int fd, quicly_conn_t *conn);
void set_alpn(ptls_handshake_properties_t *pro, const char *alpn_str);
void enqueue_requests(quicly_conn_t *conn);
int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src);
void load_ticket(ptls_handshake_properties_t* hs_properties,
                        quicly_transport_parameters_t* resumed_transport_params);

#endif //PICOQUIC_TEST_QUICLY_STUFF_HPP
