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


server::server() :
    running_(true),
    host_("0.0.0.0"),
    port_("4433"),
    fd_(-1),
    closed_by_peer_{&on_closed_by_peer},
    stream_open_{&server_on_stream_open},
    save_ticket_{save_ticket_cb},
    num_conns_(0),
    enforce_retry_(false),
    salen_(sizeof(sockaddr)) {
  memset(&tlsctx_, 0, sizeof(ptls_context_t));
  tlsctx_.random_bytes = ptls_openssl_random_bytes;
  tlsctx_.get_time = &ptls_get_time;
  tlsctx_.key_exchanges = key_exchanges_;
  tlsctx_.cipher_suites = ptls_openssl_cipher_suites;
  tlsctx_.require_dhe_on_psk = 1;
  tlsctx_.save_ticket = &save_ticket_;
}

void server::operator()() {
  if ((fd_ = socket(sa_.sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    throw std::runtime_error("socket(2) failed");
  }
  int on = 1;
  if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
    throw std::runtime_error("setsockopt(SO_REUSEADDR) failed");
  }
  if (bind(fd_, &sa_, salen_) != 0) {
    throw std::runtime_error("bind(2) failed");
  }

  std::cout << "server running!" << std::endl;
  while (running_) {
    fd_set readfds;
    timeval *tv, tvbuf = {};
    do {
      int64_t timeout_at = INT64_MAX;
      size_t i;
      for (i = 0; i != num_conns_; ++i) {
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
        tv = nullptr;
      }
      FD_ZERO(&readfds);
      FD_SET(fd_, &readfds);
    } while (select(fd_ + 1, &readfds, nullptr, nullptr, tv) == -1 && errno == EINTR);
    if (FD_ISSET(fd_, &readfds)) {
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
      while ((rret = recvmsg(fd_, &mess, 0)) <= 0);
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
            assert(rp != nullptr);
            if (send_one(fd_, rp) == -1)
              perror("sendmsg failed");
            break;
          }
        }
        quicly_conn_t *conn = nullptr;
        size_t i;
        for (i = 0; i != num_conns_; ++i) {
          if (quicly_is_destination(conns_[i], &sa, salen_, &packet)) {
            conn = conns_[i];
            break;
          }
        }
        if (conn != nullptr) {
          /* existing connection */
          quicly_receive(conn, &packet);
        } else if (QUICLY_PACKET_IS_LONG_HEADER(packet.octets.base[0])) {
          /* long header packet; potentially a new connection */
          if (enforce_retry_ && packet.token.len == 0 && packet.cid.dest.encrypted.len >= 8) {
            /* unbound connection; send a retry token unless the client has supplied the correct one, but not too many
             */
            uint8_t new_server_cid[8];
            memcpy(new_server_cid, packet.cid.dest.encrypted.base, sizeof(new_server_cid));
            new_server_cid[0] ^= 0xff;
            quicly_datagram_t *rp = quicly_send_retry(
                &ctx, &sa, salen_, packet.cid.src, ptls_iovec_init(new_server_cid, sizeof(new_server_cid)),
                packet.cid.dest.encrypted, packet.cid.dest.encrypted /* FIXME SMAC(odcid || sockaddr) */);
            assert(rp != nullptr);
            if (send_one(fd_, rp) == -1)
              perror("sendmsg failed");
            break;
          } else {
            /* new connection */
            int ret = quicly_accept(&conn, &ctx, &sa, mess.msg_namelen, &packet,
                                    enforce_retry_ ? packet.token /* a production server should validate the token */
                                                  : ptls_iovec_init(nullptr, 0),
                                    &next_cid_, nullptr);
            if (ret == 0) {
              assert(conn != nullptr);
              ++next_cid_.master_id;
              conns_ = static_cast<quicly_conn_t**>(realloc(conns_, sizeof(*conns_) * (num_conns_ + 1)));
              assert(conns_ != nullptr);
              conns_[num_conns_++] = conn;
            } else {
              assert(conn == nullptr);
            }
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
      for (i = 0; i != num_conns_; ++i) {
        if (quicly_get_first_timeout(conns_[i]) <= ctx.now->cb(ctx.now)) {
          if (send_pending(fd_, conns_[i]) != 0) {
            quicly_free(conns_[i]);
            memmove(conns_ + i, conns_ + i + 1, (num_conns_ - i - 1) * sizeof(*conns_));
            --i;
            --num_conns_;
          }
        }
      }
    }
  }
}

void server::stop() {
  running_ = false;
  shutdown(fd_, SHUT_RDWR);
  close(fd_);
}

void server::init() {
  ctx = quicly_default_context;
  ctx.tls = &tlsctx_;
  ctx.stream_open = &stream_open_;
  ctx.closed_by_peer = &closed_by_peer_;

  setup_session_cache(ctx.tls);
  quicly_amend_ptls_context(ctx.tls);

  load_certificate_chain(ctx.tls, "/home/boss/CLionProjects/quicly-chat/quicly/t/assets/server.crt");
  load_private_key(ctx.tls, "/home/boss/CLionProjects/quicly-chat/quicly/t/assets/server.key");

  req_paths[0] = const_cast<char*>("/");
  key_exchanges_[0] = &ptls_openssl_secp256r1;

  char random_key[17];
  tlsctx_.random_bytes(random_key, sizeof(random_key) - 1);
  memcpy(random_key, cid_key_, sizeof(random_key)); // save cid_key

  ctx.cid_encryptor =
      quicly_new_default_cid_encryptor(&ptls_openssl_bfecb, &ptls_openssl_sha256,
          ptls_iovec_init(cid_key_, strlen(cid_key_)));

  if (resolve_address(&sa_, &salen_, host_.c_str(), port_.c_str(), AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0)
    throw std::runtime_error("resolve address failed");
}

int main(int argc, char **argv) {
  server serv;
  serv.init();
  std::thread t_serv(std::ref(serv));

  std::string dummy;
  std::getline(std::cin, dummy);
  serv.stop();
  t_serv.join();
}
