//
// Created by boss on 31.03.19.
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
  int init();

private:
  int fd_;
  bool running_ = true;
  std::string host_;
  std::string port_;
  sockaddr sa_;
  socklen_t salen_;
  quicly_cid_plaintext_t next_cid_;
  ptls_handshake_properties_t hs_properties_;
  quicly_transport_parameters_t resumed_transport_params_;
  quicly_closed_by_peer_t closed_by_peer_;
  quicly_stream_open_t stream_open_;
  ptls_save_ticket_t save_ticket_;
  ptls_key_exchange_algorithm_t *key_exchanges_[128];
  ptls_context_t tlsctx_;
  quicly_conn_t **conns_;
  size_t num_conns_;
  char* cid_key_;
};


#endif //PICOQUIC_TEST_CLIENT_HPP
