//
// Created by Jakob on 31.03.19.
//

#ifndef PICOQUIC_TEST_CLIENT_HPP
#define PICOQUIC_TEST_CLIENT_HPP

#include "quicly_stuff.hpp"
#include <string>

class client {
public:
  client();
  ~client() = default;

  void operator()();
  void stop();
  void init();
  void send(const char* buf, int amount);

private:
  static quicly_stream_callbacks_t stream_callbacks;
  static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
  static int on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);

  int control_sockets_[2];
    // thread stuff
  bool running_ = true;
  // connection info
  std::string host_;
  std::string port_;
  // session key
  char* cid_key_;
  sockaddr_storage sa_;
  socklen_t salen_;

  quicly_cid_plaintext_t next_cid_;
  ptls_handshake_properties_t hs_properties_;
  quicly_transport_parameters_t resumed_transport_params_;
  quicly_closed_by_peer_t closed_by_peer_;
  quicly_stream_open_t stream_open_;
  ptls_save_ticket_t save_ticket_;
  ptls_key_exchange_algorithm_t *key_exchanges_[128];
  ptls_context_t tlsctx_;
  quicly_conn_t_ptr conn_;
  int fd_;
};


#endif //PICOQUIC_TEST_CLIENT_HPP
