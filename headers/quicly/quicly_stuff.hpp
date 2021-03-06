//
// Created by boss on 31.03.19.
//

#ifndef PICOQUIC_TEST_QUICLY_STUFF_HPP
#define PICOQUIC_TEST_QUICLY_STUFF_HPP

#include <memory>
#include <iostream>
extern "C" {
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "picotls/util.h"
}

extern quicly_context_t ctx;

void send_str(quicly_stream_t *stream, const char *s);
int on_stop_sending(quicly_stream_t *stream, int err);
int on_receive_reset(quicly_stream_t *stream, int err);
void on_closed_by_peer(quicly_closed_by_peer_t *self, quicly_conn_t *conn,
                       int err, uint64_t frame_type, const char *reason,
                              size_t reason_len);
int send_one(int fd, quicly_datagram_t *p);
int send_pending(int fd, quicly_conn_t *conn);
void set_alpn(ptls_handshake_properties_t *pro, const char *alpn_str);
int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src);
void load_ticket(ptls_handshake_properties_t* hs_properties,
                        quicly_transport_parameters_t* resumed_transport_params);

// TODO: this is for connection objects. Should wrap every raw ptr in this.
struct quicly_conn_t_deleter {
  void operator()(quicly_conn_t* conn) {
    quicly_free(conn);
  }
};

using quicly_conn_t_ptr = std::unique_ptr<quicly_conn_t, quicly_conn_t_deleter>;

#endif //PICOQUIC_TEST_QUICLY_STUFF_HPP
