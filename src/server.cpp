/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <getopt.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <thread>
#include "quicly/server.hpp"
#include "quicly/quicly_stuff.hpp"

int server::fd_ = -1;
std::vector<quicly_conn_t*> server::conns_;
quicly_stream_callbacks_t server::stream_callbacks = {
    quicly_streambuf_destroy,
    quicly_streambuf_egress_shift,
    quicly_streambuf_egress_emit,
    on_stop_sending,
    on_receive,
    on_receive_reset
};

server::server() :
    running_(true),
    host_("0.0.0.0"),
    port_("4433"),
    cid_key_(),
    next_cid_(),
    hs_properties_(),
    closed_by_peer_{&on_closed_by_peer},
    stream_open_{&on_stream_open},
    save_ticket_{save_ticket_cb},
    key_exchanges_(),
    tlsctx_(),
    enforce_retry_(false),
    sa_(),
    salen_(sizeof(sockaddr)) {}

/**
 * init function for server object
 */
void server::init() {
  socketpair(PF_LOCAL, SOCK_DGRAM, 0, control_sockets_);

  memset(&tlsctx_, 0, sizeof(ptls_context_t));
  tlsctx_.random_bytes = ptls_openssl_random_bytes;
  tlsctx_.get_time = &ptls_get_time;
  tlsctx_.key_exchanges = key_exchanges_;
  tlsctx_.cipher_suites = ptls_openssl_cipher_suites;
  tlsctx_.require_dhe_on_psk = true;
  tlsctx_.save_ticket = &save_ticket_;

  ctx = quicly_spec_context;
  ctx.tls = &tlsctx_;
  ctx.stream_open = &stream_open_;
  ctx.closed_by_peer = &closed_by_peer_;

  setup_session_cache(ctx.tls);
  quicly_amend_ptls_context(ctx.tls);

  std::string path_to_certs;
  char* path = getenv("QUICLY_CERTS");
  if (path) {
    path_to_certs = path;
  } else {
    // try to load defailt certs
    path_to_certs = "/home/jakob/CLionProjects/quicly-chat/quicly/t/assets/";
  }
  load_certificate_chain(ctx.tls, (path_to_certs + "server.crt").c_str());
  load_private_key(ctx.tls, (path_to_certs + "server.key").c_str());

  key_exchanges_[0] = &ptls_openssl_secp256r1;

  char random_key[17];
  tlsctx_.random_bytes(random_key, sizeof(random_key) - 1);
  memcpy(cid_key_, random_key, sizeof(random_key)); // save cid_key

  ctx.cid_encryptor =
      quicly_new_default_cid_encryptor(&ptls_openssl_bfecb, &ptls_openssl_sha256,
                                       ptls_iovec_init(cid_key_, strlen(cid_key_)));

  if (resolve_address(&sa_, &salen_, host_.c_str(), port_.c_str(), AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0)
    throw std::runtime_error("resolve address failed");
}

/**
 * server operator for startin the receiving thread
 */
void server::operator()() {
  int verbosity = 2;
  if ((fd_ = socket(sa_.sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    throw std::runtime_error("socket(2) failed");
  }
  int on = 1;
  if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
    throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");
  }
  if (bind(fd_, reinterpret_cast<sockaddr*>(&sa_), salen_) != 0) {
    throw std::runtime_error("bind(2) failed");
  }

  std::cout << "server running" << std::endl;
  while (running_) {
    fd_set readfds;
    struct timeval *tv, tvbuf;
    do {
      int64_t timeout_at = INT64_MAX;
      size_t i;
      for (i = 0; i != conns_.size(); ++i) {
        int64_t conn_to = quicly_get_first_timeout(conns_[i]);
        if (conn_to < timeout_at)
          timeout_at = conn_to;
      }
      if (timeout_at != INT64_MAX) {
        int64_t delta = timeout_at - ctx.now->cb(ctx.now);
        if (delta > 0) {
          tvbuf.tv_sec = delta / 1000;
          tvbuf.tv_usec = (delta % 1000) * 1000;
        } else {
          tvbuf.tv_sec = 0;
          tvbuf.tv_usec = 0;
        }
        tv = &tvbuf;
      } else {
        tv = NULL;
      }
      FD_ZERO(&readfds);
      FD_SET(fd_, &readfds);
      FD_SET(control_sockets_[0], &readfds);
    } while (select(fd_ + 1, &readfds, NULL, NULL, tv) == -1 && errno == EINTR && running_);
    if (FD_ISSET(fd_, &readfds) && running_) {
      uint8_t buf[4096];
      msghdr mess = {};
      sockaddr sa = {};
      iovec vec = {};
      memset(&mess, 0, sizeof(mess));
      mess.msg_name = &sa;
      mess.msg_namelen = sizeof(sa);
      vec.iov_base = buf;
      vec.iov_len = sizeof(buf);
      mess.msg_iov = &vec;
      mess.msg_iovlen = 1;
      ssize_t rret;
      while ((rret = recvmsg(fd_, &mess, 0)) <= 0)
        ;
      if (verbosity >= 2)
        std::cout << "recvmsg" << std::endl;
      size_t off = 0;
      while (off != rret) {
        quicly_decoded_packet_t packet;
        size_t plen = quicly_decode_packet(&ctx, &packet, buf + off, rret - off);
        if (plen == SIZE_MAX)
          break;
        if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
          if (packet.version != QUICLY_PROTOCOL_VERSION) {
            quicly_datagram_t *rp =
                quicly_send_version_negotiation(&ctx, &sa, salen_, packet.cid.src, packet.cid.dest.encrypted);
            assert(rp != NULL);
            if (send_one(fd_, rp) == -1)
              perror("sendmsg failed");
            break;
          }
        }
        quicly_conn_t *conn = NULL;
        size_t i;
        for (i = 0; i != conns_.size(); ++i) {
          if (quicly_is_destination(conns_[i], &sa, salen_, &packet)) {
            conn = conns_[i];
            break;
          }
        }
        if (conn != NULL) {
          /* existing connection */
          quicly_receive(conn, &packet);
        } else if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
          /* new connection */
          int ret = quicly_accept(&conn, &ctx, &sa, mess.msg_namelen, &packet,
                                  enforce_retry_ ? packet.token /* a production server should validate the token */
                                                : ptls_iovec_init(NULL, 0),
                                  &next_cid_, NULL);
          if (ret == 0) {
            assert(conn != NULL);
            ++next_cid_.master_id;
            conns_.emplace_back(conn);
            std::cout << "conns_.size() = " << conns_.size() << std::endl;
          } else {
            assert(conn == NULL);
          }
        } else {
          /* short header packet; potentially a dead connection. No need to check the length of the incoming packet,
           * because loop is prevented by authenticating the CID (by checking node_id and thread_id). If the peer is also
           * sending a reset, then the next CID is highly likely to contain a non-authenticating CID, ... */
          if (packet.cid.dest.plaintext.node_id == 0 && packet.cid.dest.plaintext.thread_id == 0) {
            quicly_datagram_t *dgram = quicly_send_stateless_reset(&ctx, &sa, salen_, packet.cid.dest.encrypted.base);
            if (send_one(fd_, dgram) == -1)
              perror("sendmsg failed");
          }
        }
        off += plen;
      }
    }
    {
      size_t i;
      for (i = 0; i != conns_.size(); ++i) {
        if (quicly_get_first_timeout(conns_[i]) <= ctx.now->cb(ctx.now)) {
          if (send_pending(fd_, conns_[i]) != 0) {
            quicly_free(conns_[i]);
            conns_.erase(conns_.begin()+i);
            --i;
            std::cout << "conns_.size() = " << conns_.size() << std::endl;
          }
        }
      }
    }
  }

  // close connections.
  for (auto& conn : conns_) {
    quicly_close(conn, 0, "");
    send_pending(fd_, conn);
    quicly_free(conn);
  }
  close(fd_);
  std::cout << "server quit" << std::endl;
}

void server::send(const char* buf, size_t amount, quicly_stream_t* from) {
  for (auto& conn : conns_) {
    if (conn == from->conn)
      continue; // skip the client that sent this data.
    // open stream for this data
    quicly_stream_t* stream;
    if (quicly_open_stream(conn, &stream, 0)) {
      throw std::runtime_error("quicly_open_stream failed");
    }

    // send data and close stream afterwards.
    quicly_streambuf_egress_write(stream, buf, amount);
    quicly_streambuf_egress_shutdown(stream);
    send_pending(fd_, conn);
  }
}

/**
 * stop function for server thread
 */
void server::stop() {
  running_ = false;
  std::string close_msg("close");
  write(control_sockets_[1], close_msg.c_str(), close_msg.length());
}

// quicly callbacks ----------------------------------------------------

int server::on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
  ptls_iovec_t input;
  int ret;

  if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
    return ret;

  if ((input = quicly_streambuf_ingress_get(stream)).len != 0) {
    send(reinterpret_cast<char*>(input.base), input.len, stream);
    quicly_streambuf_ingress_shift(stream, input.len);
  }
  return 0;
}

int server::on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
    return ret;
  stream->callbacks = &stream_callbacks;
  return 0;
}

int main(int argc, char **argv) {
  server serv;

  try {
    serv.init();
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    return -1;
  }
  std::thread t_serv(std::ref(serv));
  std::string msg;
  while (std::getline(std::cin, msg)) {
    if (msg == "/quit") {
      break;
    }
  }

  serv.stop();
  t_serv.join();
  return 0;
}
