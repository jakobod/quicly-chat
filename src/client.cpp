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

#include "quicly/quicly_stuff.hpp"
#include "quicly/client.hpp"

quicly_stream_callbacks_t client::stream_callbacks = {
    quicly_streambuf_destroy,
    quicly_streambuf_egress_shift,
    quicly_streambuf_egress_emit,
    on_stop_sending,
    on_receive,
    on_receive_reset
};

client::client() :
                  running_(true),
                  host_("localhost"),
                  port_("4433"),
                  cid_key_(nullptr),
                  sa_(),
                  salen_(0),
                  next_cid_(),
                  hs_properties_(),
                  resumed_transport_params_(),
                  closed_by_peer_{&on_closed_by_peer},
                  stream_open_{&on_stream_open},
                  save_ticket_{&save_ticket_cb},
                  key_exchanges_(),
                  tlsctx_(),
                  conn_(nullptr),
                  fd_(-1) {}

void client::init() {
  // make a socketpair to quit this program.
  socketpair(PF_LOCAL, SOCK_DGRAM, 0, control_sockets_);

  memset(&tlsctx_, 0, sizeof(ptls_context_t));
  tlsctx_.random_bytes = ptls_openssl_random_bytes;
  tlsctx_.get_time = &ptls_get_time;
  tlsctx_.key_exchanges = key_exchanges_;
  tlsctx_.cipher_suites = ptls_openssl_cipher_suites;
  tlsctx_.require_dhe_on_psk = 1;
  tlsctx_.save_ticket = &save_ticket_;

  ctx = quicly_spec_context;
  ctx.tls = &tlsctx_;
  ctx.stream_open = &stream_open_;
  ctx.closed_by_peer = &closed_by_peer_;
  
  setup_session_cache(ctx.tls);
  quicly_amend_ptls_context(ctx.tls);

  key_exchanges_[0] = &ptls_openssl_secp256r1;
  load_ticket(&hs_properties_, &resumed_transport_params_);

  if (resolve_address(reinterpret_cast<sockaddr*>(&sa_), &salen_, host_.c_str(), port_.c_str(), AF_INET,
                      SOCK_DGRAM, IPPROTO_UDP) != 0) {
    throw std::runtime_error("could not resolve address");
  }
}

void client::operator()() {
  int ret;
  sockaddr_in local = {};

  if ((fd_ = socket(reinterpret_cast<sockaddr*>(&sa_)->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    throw std::runtime_error("socket(2) failed");
  }

  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  if (bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
    throw std::runtime_error("bind(2) failed");
  }
  quicly_conn_t* conn;
  if (quicly_connect(&conn, &ctx, host_.c_str(), reinterpret_cast<sockaddr*>(&sa_), salen_, &next_cid_,
                       &hs_properties_, &resumed_transport_params_)) {
    throw std::runtime_error("quicly_connect failed");
  }
  conn_.reset(conn);

  ++next_cid_.master_id;
  //send_pending(fd_, conn_);

  while (running_) {
    fd_set readfds;
    timeval *tv, tvbuf = {};
    do {
      int64_t timeout_at = conn_ != nullptr ? quicly_get_first_timeout(conn_.get()) : INT64_MAX;
      if (timeout_at != INT64_MAX) {
        quicly_context_t *ctx = quicly_get_context(conn_.get());
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
      FD_SET(control_sockets_[0], &readfds);
    } while (select(fd_ + 1, &readfds, nullptr, nullptr, tv) == -1 && errno == EINTR && running_);
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
      while ((rret = recvmsg(fd_, &mess, 0)) <= 0);
      size_t off = 0;
      while (off != rret) {
        quicly_decoded_packet_t packet;
        size_t plen = quicly_decode_packet(&ctx, &packet, buf + off, rret - off);
        if (plen == SIZE_MAX)
          break;
        quicly_receive(conn_.get(), &packet);
        off += plen;
      }
    }
    if (conn_ != nullptr) {
      ret = send_pending(fd_, conn_.get());
      if (ret != 0) {
        conn_.reset();
        if (ret == QUICLY_ERROR_FREE_CONNECTION) {
          throw std::runtime_error("QUICLY_ERROR_FREE_CONNECTION");
        } else {
          std::cout << "quicly_send returned " << ret << std::endl;
          break;
        }
      }
    }
  }

  // close connection.
  quicly_close(conn_.get(), 0, "");
  send_pending(fd_, conn_.get());
  close(fd_);
  std::cout << "client quit" << std::endl;
}

void client::send(const char* buf, int amount) {
  // open stream for this data
  quicly_stream_t* stream;
  if (quicly_open_stream(conn_.get(), &stream, 0)) {
    throw std::runtime_error("quicly_open_stream failed");
  }

  // send data and close stream afterwards.
  quicly_streambuf_egress_write(stream, buf, amount);
  quicly_streambuf_egress_shutdown(stream);
  send_pending(fd_, conn_.get());
}

void client::stop() {
  running_ = false;
  //shutdown(fd_, SHUT_RDWR);
  std::string close_msg("close");
  write(control_sockets_[1], close_msg.c_str(), close_msg.length());
  //close(fd_);
}

// client quicly callbacks -----------------------------------------------------

int client::on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
    return ret;
  stream->callbacks = &stream_callbacks;
  return 0;
}

int client::on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
  ptls_iovec_t input;
  int ret;

  if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
    return ret;

  if ((input = quicly_streambuf_ingress_get(stream)).len != 0) {
    std::string msg(reinterpret_cast<char*>(input.base), input.len);
    std::cout << "received: " << msg << std::endl;
    quicly_streambuf_ingress_shift(stream, input.len);
  }

  return 0;
}

int main(int argc, char **argv) {
  client cli;

  try {
    cli.init();
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    return -1;
  }
  std::thread t_cli(std::ref(cli));

  std::cout << "please enter your chat messages:" << std::endl;
  std::string msg;
  while (std::getline(std::cin, msg)) {
    if (msg == "/quit") {
      break;
    } else {
      cli.send(msg.c_str(), msg.length());
    }
  }

  cli.stop();
  t_cli.join();
  return 0;
}
