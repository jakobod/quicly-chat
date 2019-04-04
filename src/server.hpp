//
// Created by boss on 31.03.19.
//

#ifndef PICOQUIC_TEST_SERVER_HPP
#define PICOQUIC_TEST_SERVER_HPP

#include "quicly_stuff.hpp"

class server {
public:
  server();
  ~server() = default;

  void operator()();
  void stop();
  void init();

private:
  bool running_;
  std::string host_;
  std::string port_;
  int fd_;
  quicly_cid_plaintext_t next_cid_;
  ptls_handshake_properties_t hs_properties_;
  quicly_closed_by_peer_t closed_by_peer_;
  quicly_stream_open_t stream_open_;
  ptls_save_ticket_t save_ticket_;
  ptls_key_exchange_algorithm_t *key_exchanges_[128];
  ptls_context_t tlsctx_;
  quicly_conn_t **conns_;
  size_t num_conns_;
  bool enforce_retry_;
  sockaddr sa_;
  socklen_t salen_;
  char cid_key_[17];
};


#endif //PICOQUIC_TEST_SERVER_HPP
