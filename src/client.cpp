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

#include "quicly_stuff.hpp"

static quicly_cid_plaintext_t next_cid;
static ptls_handshake_properties_t hs_properties;
static quicly_transport_parameters_t resumed_transport_params;

static quicly_closed_by_peer_t closed_by_peer = {&on_closed_by_peer};
static quicly_stream_open_t stream_open = {&client_on_stream_open};
static ptls_save_ticket_t save_ticket = {save_ticket_cb};

ptls_key_exchange_algorithm_t *key_exchanges[128];
static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
    .get_time = &ptls_get_time,
    .key_exchanges = key_exchanges,
    .cipher_suites = ptls_openssl_cipher_suites,
    .require_dhe_on_psk = 1,
    .save_ticket = &save_ticket};

static quicly_conn_t **conns;
static size_t num_conns = 0;

static void on_signal(int signo) {
  size_t i;
  for (i = 0; i != num_conns; ++i) {
    const quicly_cid_plaintext_t *master_id = quicly_get_master_id(conns[i]);
    uint64_t num_received, num_sent, num_lost, num_ack_received, num_bytes_sent;
    quicly_get_packet_stats(conns[i], &num_received, &num_sent, &num_lost, &num_ack_received, &num_bytes_sent);
    fprintf(stderr,
            "conn:%08" PRIu32 ": received: %" PRIu64 ", sent: %" PRIu64 ", lost: %" PRIu64 ", ack-received: %" PRIu64
            ", bytes-sent: %" PRIu64 "\n",
            master_id->master_id, num_received, num_sent, num_lost, num_ack_received, num_bytes_sent);
  }
  if (signo == SIGINT)
    _exit(0);
}

void enqueue_requests(quicly_conn_t *conn) {
  size_t i;
  int ret;

  for (i = 0; req_paths[i] != nullptr; ++i) {
    char req[1024];
    quicly_stream_t *stream;
    ret = quicly_open_stream(conn, &stream, 0);
    assert(ret == 0);
    sprintf(req, "GET %s\r\n", req_paths[i]);
    send_str(stream, req);
    quicly_streambuf_egress_shutdown(stream);
  }
  enqueue_requests_at = INT64_MAX;
}

static int run_client(sockaddr *sa, socklen_t salen, const char *host)
{
  int fd, ret;
  sockaddr_in local = {};
  quicly_conn_t *conn = nullptr;

  if ((fd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    perror("socket(2) failed");
    return 1;
  }
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  if (bind(fd, (sockaddr*) &local, sizeof(local)) != 0) {
    perror("bind(2) failed");
    return 1;
  }
  ret = quicly_connect(&conn, &ctx, host, sa, salen, &next_cid, &hs_properties, &resumed_transport_params);
  assert(ret == 0);
  ++next_cid.master_id;
  enqueue_requests(conn);
  send_pending(fd, conn);

  while (true) {
    fd_set readfds;
    timeval *tv, tvbuf = {};
    do {
      int64_t timeout_at = conn != nullptr ? quicly_get_first_timeout(conn) : INT64_MAX;
      if (enqueue_requests_at < timeout_at)
        timeout_at = enqueue_requests_at;
      if (timeout_at != INT64_MAX) {
        quicly_context_t *ctx = quicly_get_context(conn);
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
      FD_SET(fd, &readfds);
    } while (select(fd + 1, &readfds, nullptr, nullptr, tv) == -1 && errno == EINTR);
    if (enqueue_requests_at <= ctx.now->cb(ctx.now))
      enqueue_requests(conn);
    if (FD_ISSET(fd, &readfds)) {
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
      while ((rret = recvmsg(fd, &mess, 0)) <= 0);
      size_t off = 0;
      while (off != rret) {
        quicly_decoded_packet_t packet;
        size_t plen = quicly_decode_packet(&ctx, &packet, buf + off, rret - off);
        if (plen == SIZE_MAX)
          break;
        quicly_receive(conn, &packet);
        off += plen;
      }
    }
    if (conn != nullptr) {
      ret = send_pending(fd, conn);
      if (ret != 0) {
        quicly_free(conn);
        conn = nullptr;
        if (ret == QUICLY_ERROR_FREE_CONNECTION) {
          return 0;
        } else {
          fprintf(stderr, "quicly_send returned %d\n", ret);
          return 1;
        }
      }
    }
  }
}

static void usage(const char *cmd) {
  printf("Usage: %s [options] host port\n"
         "\n"
         "Options:\n"
         "  -a <alpn list>       a coma separated list of ALPN identifiers\n"
         "  -C <cid-key>         CID encryption key (server-only). Randomly generated\n"
         "                       if omitted.\n"
         "  -c certificate-file\n"
         "  -k key-file          specifies the credentials to be used for running the\n"
         "                       server. If omitted, the command runs as a client.\n"
         "  -e event-log-file    file to log events\n"
         "  -i interval          interval to reissue requests (in milliseconds)\n"
         "  -l log-file          file to log traffic secrets\n"
         "  -M <bytes>           max stream data (in bytes; default: 1MB)\n"
         "  -m <bytes>           max data (in bytes; default: 16MB)\n"
         "  -N                   enforce HelloRetryRequest (client-only)\n"
         "  -n                   enforce version negotiation (client-only)\n"
         "  -p path              path to request (can be set multiple times)\n"
         "  -r [initial-rto]     initial RTO (in milliseconds)\n"
         "  -V                   verify peer using the default certificates\n"
         "  -v                   verbose mode (-vv emits packet dumps as well)\n"
         "  -x named-group       named group to be used (default: secp256r1)\n"
         "  -X                   max bidirectional stream count (default: 100)\n"
         "  -h                   print this help\n"
         "\n",
         cmd);
}

int main(int argc, char **argv) {
  const char *host, *port, *cid_key = nullptr;
  sockaddr_storage sa = {};
  socklen_t salen;
  int ch;

  ctx = quicly_default_context;
  ctx.tls = &tlsctx;
  ctx.stream_open = &stream_open;
  ctx.closed_by_peer = &closed_by_peer;

  setup_session_cache(ctx.tls);
  quicly_amend_ptls_context(ctx.tls);

  while ((ch = getopt(argc, argv, "a:C:c:k:e:i:l:M:m:Nnp:Rr:s:Vvx:X:h")) != -1) {
    switch (ch) {
      case 'a':
        set_alpn(&hs_properties, optarg);
        break;
      case 'C':
        cid_key = optarg;
        break;
      case 'c':
        load_certificate_chain(ctx.tls, optarg);
        break;
      case 'k':
        load_private_key(ctx.tls, optarg);
        break;
      case 'e': {
        FILE *fp;
        if ((fp = fopen(optarg, "w")) == nullptr) {
          fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
          exit(1);
        }
        setvbuf(fp, nullptr, _IONBF, 0);
        ctx.event_log.mask = UINT64_MAX;
        ctx.event_log.cb = quicly_new_default_event_logger(fp);
      } break;
      case 'i':
        if (sscanf(optarg, "%" PRId64, &request_interval) != 1) {
          fprintf(stderr, "failed to parse request interval: %s\n", optarg);
          exit(1);
        }
        break;
      case 'l':
        setup_log_event(ctx.tls, optarg);
        break;
      case 'M': {
        uint64_t v;
        if (sscanf(optarg, "%" PRIu64, &v) != 1) {
          fprintf(stderr, "failed to parse max stream data:%s\n", optarg);
          exit(1);
        }
        ctx.transport_params.max_stream_data.bidi_local = v;
        ctx.transport_params.max_stream_data.bidi_remote = v;
        ctx.transport_params.max_stream_data.uni = v;
      } break;
      case 'm':
        if (sscanf(optarg, "%" PRIu64, &ctx.transport_params.max_data) != 1) {
          fprintf(stderr, "failed to parse max data:%s\n", optarg);
          exit(1);
        }
        break;
      case 'N':
        hs_properties.client.negotiate_before_key_exchange = 1;
        break;
      case 'n':
        ctx.enforce_version_negotiation = 1;
        break;
      case 'p': {
        size_t i;
        for (i = 0; req_paths[i] != nullptr; ++i)
          ;
        req_paths[i] = optarg;
      } break;
      case 'r':
        if (sscanf(optarg, "%" PRIu32, &ctx.loss->default_initial_rtt) != 1) {
          fprintf(stderr, "invalid argument passed to `-r`\n");
          exit(1);
        }
        break;
      case 'V':
        setup_verify_certificate(ctx.tls);
        break;
      case 'x': {
        size_t i;
        for (i = 0; key_exchanges[i] != nullptr; ++i)
          ;
#define MATCH(name)                                                                                                                \
    if (key_exchanges[i] == nullptr && strcasecmp(optarg, #name) == 0)                                                                \
    key_exchanges[i] = &ptls_openssl_##name
        MATCH(secp256r1);
#if PTLS_OPENSSL_HAVE_SECP384R1
        MATCH(secp384r1);
#endif
#if PTLS_OPENSSL_HAVE_SECP521R1
        MATCH(secp521r1);
#endif
#if PTLS_OPENSSL_HAVE_X25519
        MATCH(x25519);
#endif
#undef MATCH
        if (key_exchanges[i] == nullptr) {
          fprintf(stderr, "unknown key exchange: %s\n", optarg);
          exit(1);
        }
      } break;
      case 'X':
        if (sscanf(optarg, "%" PRIu64, &ctx.transport_params.max_streams_bidi) != 1) {
          fprintf(stderr, "failed to parse max streams count: %s\n", optarg);
          exit(1);
        }
        break;
      default:
        usage(argv[0]);
        exit(1);
    }
  }
  argc -= optind;
  argv += optind;

  if (req_paths[0] == nullptr)
    req_paths[0] = const_cast<char*>("/");

  if (key_exchanges[0] == nullptr)
    key_exchanges[0] = &ptls_openssl_secp256r1;
  if (cid_key == nullptr) {
    static char random_key[17];
    tlsctx.random_bytes(random_key, sizeof(random_key) - 1);
    cid_key = random_key;
  }
  ctx.cid_encryptor =
      quicly_new_default_cid_encryptor(&ptls_openssl_bfecb, &ptls_openssl_sha256, ptls_iovec_init(cid_key, strlen(cid_key)));

  host = "localhost";
  port = "4433";

  std::cout << "connecting to host: " << host << " port: " << port << std::endl;
  if (resolve_address((sockaddr*)&sa, &salen, host, port, AF_INET, SOCK_DGRAM, IPPROTO_UDP) != 0)
    exit(1);

  return run_client((sockaddr*)&sa, salen, host);
}
