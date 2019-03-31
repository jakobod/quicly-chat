//
// Created by boss on 31.03.19.
//

#ifndef PICOQUIC_TEST_CLIENT_HPP
#define PICOQUIC_TEST_CLIENT_HPP

#include "quicly_stuff.hpp"

class client {
public:
  client() = default;
  ~client() = default;

  void operator()();
  void stop();
  int init();

private:
  void on_signal(int signo);

  int fd_;
  bool running_ = true;
  std::string host;
  std::string port;
  sockaddr sa;
  socklen_t salen;
  quicly_cid_plaintext_t next_cid;
  ptls_handshake_properties_t hs_properties;
  quicly_transport_parameters_t resumed_transport_params;
  quicly_closed_by_peer_t closed_by_peer = {&on_closed_by_peer};
  quicly_stream_open_t stream_open = {&client_on_stream_open};
  ptls_save_ticket_t save_ticket = {save_ticket_cb};
  ptls_key_exchange_algorithm_t *key_exchanges[128];
  ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
      .get_time = &ptls_get_time,
      .key_exchanges = key_exchanges,
      .cipher_suites = ptls_openssl_cipher_suites,
      .require_dhe_on_psk = 1,
      .save_ticket = &save_ticket};
  quicly_conn_t **conns;
  size_t num_conns = 0;
  char* cid_key = nullptr;
};


#endif //PICOQUIC_TEST_CLIENT_HPP
