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

#include "quicly_stuff.hpp"
#include "client.hpp"

client::client() :
                  fd_(-1),
                  running_(true),
                  host_("localhost"),
                  port_("4433"),
                  sa_(),
                  salen_(0),
                  next_cid_(),
                  hs_properties_(),
                  resumed_transport_params_(),
                  closed_by_peer_{&on_closed_by_peer},
                  stream_open_{&client_on_stream_open},
                  save_ticket_{&save_ticket_cb},
                  conn_(nullptr),
                  cid_key_(nullptr) {
  memset(&tlsctx_, 0, sizeof(ptls_context_t));
  tlsctx_.random_bytes = ptls_openssl_random_bytes;
  tlsctx_.get_time = &ptls_get_time;
  tlsctx_.key_exchanges = key_exchanges_;
  tlsctx_.cipher_suites = ptls_openssl_cipher_suites;
  tlsctx_.require_dhe_on_psk = 1;
  tlsctx_.save_ticket = &save_ticket_;
}

int client::init() {
  ctx = quicly_default_context;
  ctx.tls = &tlsctx_;
  ctx.stream_open = &stream_open_;
  ctx.closed_by_peer = &closed_by_peer_;
  
  setup_session_cache(ctx.tls);
  quicly_amend_ptls_context(ctx.tls);

  req_paths[0] = const_cast<char*>("/");
  key_exchanges_[0] = &ptls_openssl_secp256r1;
  load_ticket(&hs_properties_, &resumed_transport_params_);

  if (resolve_address(&sa_, &salen_, host_.c_str(), port_.c_str(), AF_INET, 
                      SOCK_DGRAM, IPPROTO_UDP) != 0) {
    throw std::runtime_error("could not resolve address");
  }
  return 0;
}

void client::operator()() {
  int ret;
  struct sockaddr_in local = {};

  if ((fd_ = socket(sa_.sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    throw std::runtime_error("socket(2) failed");
  }

  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  if (bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
    throw std::runtime_error("bind(2) failed");
  }
  // TODO: this throws.. why tho?
  if (quicly_connect(&conn_, &ctx, host_.c_str(), &sa_, salen_, &next_cid_, 
                       &hs_properties_, &resumed_transport_params_)) {
    throw std::runtime_error("quicly_connect failed");
  }

  ++next_cid_.master_id;
  enqueue_requests(conn_);
  send_pending(fd_, conn_);

  while (running_) {
    fd_set readfds;
    timeval *tv, tvbuf = {};
    do {
      int64_t timeout_at = conn_ != nullptr ? quicly_get_first_timeout(conn_) : INT64_MAX;
      if (enqueue_requests_at < timeout_at)
        timeout_at = enqueue_requests_at;
      if (timeout_at != INT64_MAX) {
        quicly_context_t *ctx = quicly_get_context(conn_);
        int64_t delta = timeout_at - ctx->now->cb(ctx->now);
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
    if (enqueue_requests_at <= ctx.now->cb(ctx.now))
      enqueue_requests(conn_);
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
        quicly_receive(conn_, &packet);
        off += plen;
      }
    }
    if (conn_ != nullptr) {
      ret = send_pending(fd_, conn_);
      if (ret != 0) {
        quicly_free(conn_);
        conn_ = nullptr;
        if (ret == QUICLY_ERROR_FREE_CONNECTION) {
          throw std::runtime_error("QUICLY_ERROR_FREE_CONNECTION");
        } else {
          std::cout << "quicly_send returned " << ret << std::endl;
          break;
        }
      }
    }
  }
  std::cout << "client quit" << std::endl;
}

void client::stop() {
  running_ = false;
  shutdown(fd_, SHUT_RDWR);
  close(fd_);
}

int main(int argc, char **argv) {
  client cli;
  cli.init();
  std::thread t_cli(std::ref(cli));

  getchar();
  cli.stop();
  t_cli.join();
  return 0;
}
