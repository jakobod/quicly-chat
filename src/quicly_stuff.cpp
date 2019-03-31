//
// Created by boss on 31.03.19.
//

#include "quicly_stuff.hpp"

static const char *ticket_file = "ticket.bin";
char *req_paths[1024];
int64_t request_interval = 0;
int64_t enqueue_requests_at = 0;
quicly_context_t ctx;

static const quicly_stream_callbacks_t client_stream_callbacks =
    {quicly_streambuf_destroy,
     quicly_streambuf_egress_shift,
     quicly_streambuf_egress_emit,
     on_stop_sending,
     client_on_receive,
     on_receive_reset};

static const quicly_stream_callbacks_t server_stream_callbacks =
    {quicly_streambuf_destroy,
     quicly_streambuf_egress_shift,
     quicly_streambuf_egress_emit,
     on_stop_sending,
     server_on_receive,
     on_receive_reset};

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

int parse_request(ptls_iovec_t input, ptls_iovec_t *path, int *is_http1) {
  size_t off = 0, path_start;

  for (off = 0; off != input.len; ++off)
    if (input.base[off] == ' ')
      goto EndOfMethod;
  return 0;

  EndOfMethod:
  ++off;
  path_start = off;
  for (; off != input.len; ++off)
    if (input.base[off] == ' ' || input.base[off] == '\r' || input.base[off] == '\n')
      goto EndOfPath;
  return 0;

  EndOfPath:
  *path = ptls_iovec_init(input.base + path_start, off - path_start);
  *is_http1 = input.base[off] == ' ';
  return 1;
}

int path_is(ptls_iovec_t path, const char *expected) {
  size_t expected_len = strlen(expected);
  if (path.len != expected_len)
    return 0;
  return memcmp(path.base, expected, path.len) == 0;
}

void send_str(quicly_stream_t *stream, const char *s) {
  quicly_streambuf_egress_write(stream, s, strlen(s));
}

void send_header(quicly_stream_t *stream, int is_http1, int status, const char *mime_type) {
  char buf[256];

  if (!is_http1)
    return;

  sprintf(buf, "HTTP/1.1 %03d OK\r\nConnection: close\r\nContent-Type: %s\r\n\r\n", status, mime_type);
  send_str(stream, buf);
}

int send_file(quicly_stream_t *stream, int is_http1, const char *fn, const char *mime_type) {
  FILE *fp;
  char buf[1024];
  size_t n;

  if ((fp = fopen(fn, "rb")) == nullptr)
    return 0;
  send_header(stream, is_http1, 200, mime_type);
  while ((n = fread(buf, 1, sizeof(buf), fp)) != 0)
    quicly_streambuf_egress_write(stream, buf, n);
  fclose(fp);

  return 1;
}

int send_sized_text(quicly_stream_t *stream, ptls_iovec_t path, int is_http1) {
  if (!(path.len > 5 && path.base[0] == '/' && memcmp(path.base + path.len - 4, ".txt", 4) == 0))
    return 0;
  unsigned size = 0;
  {
    const char *p;
    for (p = (const char *)path.base + 1; *p != '.'; ++p) {
      if (!('0' <= *p && *p <= '9'))
        return 0;
      size = size * 10 + (*p - '0');
    }
  }

  send_header(stream, is_http1, 200, "text/plain; charset=utf-8");
  for (; size >= 12; size -= 12)
    quicly_streambuf_egress_write(stream, "hello world\n", 12);
  if (size != 0)
    quicly_streambuf_egress_write(stream, "hello world", size);
  return 1;
}

int on_stop_sending(quicly_stream_t *stream, int err) {
  assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
  fprintf(stderr, "received STOP_SENDING: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
  return 0;
}

int on_receive_reset(quicly_stream_t *stream, int err) {
  assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
  fprintf(stderr, "received RESET_STREAM: %" PRIu16 "\n", QUICLY_ERROR_GET_ERROR_CODE(err));
  return 0;
}

int server_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
    return ret;
  stream->callbacks = &server_stream_callbacks;
  return 0;
}

int client_on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
  int ret;

  if ((ret = quicly_streambuf_create(stream, sizeof(quicly_streambuf_t))) != 0)
    return ret;
  stream->callbacks = &client_stream_callbacks;
  return 0;
}

void on_closed_by_peer(quicly_closed_by_peer_t *self, quicly_conn_t *conn, int err, uint64_t frame_type, const char *reason,
                              size_t reason_len) {
  if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
    fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
            frame_type, (int)reason_len, reason);
  } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
    fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
            reason);
  } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
    fprintf(stderr, "stateless reset\n");
  } else {
    fprintf(stderr, "unexpected close:code=%d\n", err);
  }
}

int send_one(int fd, quicly_datagram_t *p) {
  int ret;
  msghdr mess = {};
  iovec vec = {};
  memset(&mess, 0, sizeof(mess));
  mess.msg_name = &p->sa;
  mess.msg_namelen = p->salen;
  vec.iov_base = p->data.base;
  vec.iov_len = p->data.len;
  mess.msg_iov = &vec;
  mess.msg_iovlen = 1;
  while ((ret = (int)sendmsg(fd, &mess, 0)) == -1 && errno == EINTR);
  return ret;
}

int send_pending(int fd, quicly_conn_t *conn) {
  quicly_datagram_t *packets[16];
  size_t num_packets, i;
  int ret;

  do {
    num_packets = sizeof(packets) / sizeof(packets[0]);
    if ((ret = quicly_send(conn, packets, &num_packets)) == 0) {
      for (i = 0; i != num_packets; ++i) {
        if ((send_one(fd, packets[i])) == -1)
          perror("sendmsg failed");
        ret = 0;
        quicly_packet_allocator_t *pa = quicly_get_context(conn)->packet_allocator;
        pa->free_packet(pa, packets[i]);
      }
    }
  } while (ret == 0 && num_packets == sizeof(packets) / sizeof(packets[0]));

  return ret;
}

void set_alpn(ptls_handshake_properties_t *pro, const char *alpn_str) {
  const char *start, *cur;
  //std::vector<ptls_iovec_t> list;
  ptls_iovec_t *list = nullptr;
  size_t entries = 0;
  start = cur = alpn_str;
#define ADD_ONE()                                                          \
    if ((cur - start) > 0) {                                               \
      list = (ptls_iovec_t*) realloc(list, sizeof(*list) * (entries + 1)); \
      list[entries].base = (uint8_t*) strndup(start, cur - start);         \
      list[entries++].len = cur - start;                                   \
}

  while (*cur) {
    if (*cur == ',') {
      ADD_ONE();
      start = cur + 1;
    }
    cur++;
  }
  if (start != cur)
    ADD_ONE();

  pro->client.negotiated_protocols.list = list;
  pro->client.negotiated_protocols.count = entries;
}

int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src) {
  auto conn = static_cast<quicly_conn_t*>(*ptls_get_data_ptr(tls));
  ptls_buffer_t buf;
  char smallbuff[512];
  FILE *fp = nullptr;
  int ret;

  if (ticket_file == nullptr)
    return 0;

  ptls_buffer_init(&buf, smallbuff, 0);

  /* build data (session ticket and transport parameters) */
  ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, src.base, src.len); });
  ptls_buffer_push_block(&buf, 2, {
    if ((ret = quicly_encode_transport_parameter_list(&buf, 1, quicly_get_peer_transport_parameters(conn), nullptr, nullptr)) != 0)
      goto Exit;
  });

  /* write file */
  if ((fp = fopen(ticket_file, "wb")) == nullptr) {
    fprintf(stderr, "failed to open file:%s:%s\n", ticket_file, strerror(errno));
    ret = PTLS_ERROR_LIBRARY;
    goto Exit;
  }
  fwrite(buf.base, 1, buf.off, fp);

  ret = 0;
  Exit:
  if (fp != nullptr)
    fclose(fp);
  ptls_buffer_dispose(&buf);
  return 0;
}

void load_ticket(ptls_handshake_properties_t* hs_properties,
                 quicly_transport_parameters_t* resumed_transport_params) {
  static uint8_t buf[65536];
  size_t len;
  int ret;


  FILE *fp;
  if ((fp = fopen(ticket_file, "rb")) == nullptr)
    return;
  len = fread(buf, 1, sizeof(buf), fp);
  if (len == 0 || !feof(fp)) {
    fprintf(stderr, "failed to load ticket from file:%s\n", ticket_file);
    exit(1);
  }
  fclose(fp);

  const uint8_t *src = buf, *end = buf + len;
  ptls_iovec_t ticket;
  ptls_decode_open_block(src, end, 2, {
    ticket = ptls_iovec_init(src, end - src);
    src = end;
  });
  ptls_decode_block(src, end, 2,
                    if ((ret = quicly_decode_transport_parameter_list(resumed_transport_params, nullptr, nullptr, 1, src, end)) != 0)
                      goto Exit;
                        src = end;
  );
  hs_properties->client.session_ticket = ticket;

  Exit:;
}

int server_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
  ptls_iovec_t path;
  int is_http1;
  int ret;

  if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
    return ret;

  if (!parse_request(quicly_streambuf_ingress_get(stream), &path, &is_http1)) {
    if (!quicly_recvstate_transfer_complete(&stream->recvstate))
      return 0;
    /* failed to parse request */
    send_header(stream, 1, 500, "text/plain; charset=utf-8");
    send_str(stream, "failed to parse HTTP request\n");
    goto Sent;
  }
  if (!quicly_recvstate_transfer_complete(&stream->recvstate))
    quicly_request_stop(stream, 0);

  if (path_is(path, "/logo.jpg") && send_file(stream, is_http1, "assets/logo.jpg", "image/jpeg"))
    goto Sent;
  if (path_is(path, "/main.jpg") && send_file(stream, is_http1, "assets/main.jpg", "image/jpeg"))
    goto Sent;
  if (send_sized_text(stream, path, is_http1))
    goto Sent;

  if (!quicly_sendstate_is_open(&stream->sendstate))
    return 0;

  send_header(stream, is_http1, 404, "text/plain; charset=utf-8");
  send_str(stream, "Hello World!!!!!!!!!!\n");
  Sent:
  quicly_streambuf_egress_shutdown(stream);
  quicly_streambuf_ingress_shift(stream, len);
  return 0;
}

int client_on_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len) {
  ptls_iovec_t input;
  int ret;

  if ((ret = quicly_streambuf_ingress_receive(stream, off, src, len)) != 0)
    return ret;

  if ((input = quicly_streambuf_ingress_get(stream)).len != 0) {
    fwrite(input.base, 1, input.len, stdout);
    fflush(stdout);
    quicly_streambuf_ingress_shift(stream, input.len);
  }

  if (quicly_recvstate_transfer_complete(&stream->recvstate)) {
    static size_t num_resp_received;
    ++num_resp_received;
    if (req_paths[num_resp_received] == nullptr) {
      if (request_interval != 0) {
        enqueue_requests_at = ctx.now->cb(ctx.now) + request_interval;
      } else {
        uint64_t num_received, num_sent, num_lost, num_ack_received, num_bytes_sent;
        quicly_get_packet_stats(stream->conn, &num_received, &num_sent, &num_lost, &num_ack_received, &num_bytes_sent);
        fprintf(stderr,
                "packets: received: %" PRIu64 ", sent: %" PRIu64 ", lost: %" PRIu64 ", ack-received: %" PRIu64
                ", bytes-sent: %" PRIu64 "\n",
                num_received, num_sent, num_lost, num_ack_received, num_bytes_sent);
        quicly_close(stream->conn, 0, "");
      }
    }
  }

  return 0;
}
