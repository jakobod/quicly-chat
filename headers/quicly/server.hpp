//
// Created by Jakob Otto on 31.03.19.
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
  static void send(const char* buf, size_t amount, quicly_stream_t* from = nullptr);

private:
  static quicly_stream_callbacks_t stream_callbacks;

  static int on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
  static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream);
  bool running_;
  std::string host_;
  std::string port_;
  char cid_key_[17];
  static int fd_;
  quicly_cid_plaintext_t next_cid_;
  ptls_handshake_properties_t hs_properties_;
  quicly_closed_by_peer_t closed_by_peer_;
  quicly_stream_open_t stream_open_;
  ptls_save_ticket_t save_ticket_;
  ptls_key_exchange_algorithm_t *key_exchanges_[128];
  ptls_context_t tlsctx_;
  static std::vector<quicly_conn_t*> conns_;
  bool enforce_retry_;
  sockaddr sa_;
  socklen_t salen_;
};


#endif //PICOQUIC_TEST_SERVER_HPP
