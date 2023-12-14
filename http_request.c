#include <gio/gio.h>
#include <glib.h>
#include <stdio.h>
#include <sysexits.h>

#include "http_request.h"

#define INPUT_BUFFER_SIZE 4000
#define GET_REQ             \
  "GET / HTTP/1.1\r\n"      \
  "Host: www.google.se\r\n" \
  "\r\n"

#define HTTP_START                "HTTP"
#define HTTPHEADER_END            "\r\n\r\n"
#define CHUNKHEADER_END           "\r\n"
#define CONTENT_LENGTH            "content-length"
#define TRANSFER_ENCODING         "transfer-encoding"
#define TRANSFER_ENCODING_LEN     -2
#define TRANSFER_ENCODING_CHUNKED "chunked"

struct header {
  gchar *name;
  gchar *value;
};

struct _HttpClient {
  GObject parent;

  GSocketClient *client;
  GCancellable *cancel;

  GHashTable *conns;
};

struct conn {
  GSocketClient *client;
  GSocketConnection *con;
  GCancellable *cancel;
  GInputStream *input;
  GOutputStream *output;
  gchar *debug;

  GList *queue;
};

struct _HttpRequest {
  GObject parent;

  struct conn *owner;
  GUri *uri;

  GOutputStream *response;
  GInputStream *send_data;

  gint status;
  gpointer raw_header;
  gsize raw_header_size;
  GList *headers;

  gchar *chunk;
  gssize chunk_len;

  GAsyncReadyCallback callback;
  gpointer user_data;

  gssize content_length;
  gint reads;
  GError *error;
};

static GQuark error_quark(void)
{
  static GQuark quark;
  if (!quark)
    quark = g_quark_from_static_string("http_request");
  return quark;
}

G_DEFINE_TYPE(HttpClient, http_client, G_TYPE_OBJECT)
G_DEFINE_TYPE(HttpRequest, http_request, G_TYPE_OBJECT)

static void write_request_done(GObject *source_object,
                               GAsyncResult *res,
                               gpointer user_data);

static void read_chunked_header(GObject *source_object,
                                GAsyncResult *res,
                                gpointer user_data);

static void init_request(HttpRequest *r);

static void
output_closed(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = (HttpRequest *) (user_data);
  GOutputStream *stream = G_OUTPUT_STREAM(source_object);
  GError *err = NULL;

  if (!g_output_stream_close_finish(stream, res, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  r->owner->queue = g_list_remove(r->owner->queue, r);

  if (r->owner->queue != NULL) {
    g_debug("Starting next request\n");
    init_request(r->owner->queue->data);
  }

  r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
}

static void
request_done(HttpRequest *r)
{
  if (r->response == NULL) {
    r->owner->queue = g_list_remove(r->owner->queue, r);

    if (r->owner->queue != NULL) {
      init_request(r->owner->queue->data);
    }

    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
  } else {
    g_output_stream_close_async(r->response, G_PRIORITY_DEFAULT,
                                r->owner->cancel, output_closed, r);
  }
}

static void
chunk_body_written(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = (HttpRequest *) user_data;
  GOutputStream *stream = G_OUTPUT_STREAM(source_object);
  gsize read;
  GError *err = NULL;

  if (!g_output_stream_write_all_finish(stream, res, &read, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  g_debug("Body writter, filling buffer");
  g_buffered_input_stream_fill_async(G_BUFFERED_INPUT_STREAM(r->owner->input),
                                     -1, G_PRIORITY_DEFAULT, r->owner->cancel,
                                     read_chunked_header, user_data);
}

static void
read_chunked_body(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = (HttpRequest *) user_data;
  GInputStream *stream = G_INPUT_STREAM(source_object);
  gsize read;
  GError *err = NULL;

  g_assert(stream);
  g_assert(res);
  g_assert(r);

  if (!g_input_stream_read_all_finish(stream, res, &read, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  g_debug("Chunk read, writing");

  g_output_stream_write_all_async(r->response, r->chunk, r->chunk_len,
                                  G_PRIORITY_DEFAULT, r->owner->cancel,
                                  chunk_body_written, user_data);
}

static void
clear_input_stream(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = HTTP_REQUEST(user_data);
  GInputStream *stream = G_INPUT_STREAM(source_object);
  gsize read;
  GError *err = NULL;

  g_assert(stream);
  g_assert(res);
  g_assert(r);

  g_clear_pointer(&r->chunk, g_free);

  if (!g_input_stream_read_all_finish(stream, res, &read, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  g_debug("Read %lu bytes trailing", read);

  request_done(r);
}

static void
parse_chunked_header(GObject *source_object,
                     GAsyncResult *res,
                     gpointer user_data)
{
  HttpRequest *r = HTTP_REQUEST(user_data);
  GInputStream *stream = G_INPUT_STREAM(source_object);
  gsize read;
  GError *err = NULL;
  gint64 chunk_len;

  g_assert(stream);
  g_assert(res);
  g_assert(r);

  if (!g_input_stream_read_all_finish(stream, res, &read, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  /* This ignores leading spaces, including \r\n */
  chunk_len = g_ascii_strtoll(r->chunk, NULL, 16);

  if (chunk_len == 0) {
    g_debug("Chunk header == 0, done");
    g_free(r->chunk);
    r->chunk = g_malloc(
      g_buffered_input_stream_get_available(G_BUFFERED_INPUT_STREAM(stream)) +
      1);
    g_input_stream_read_all_async(stream, r->chunk,
                                  g_buffered_input_stream_get_available(
                                    G_BUFFERED_INPUT_STREAM(stream)),
                                  G_PRIORITY_DEFAULT, r->owner->cancel,
                                  clear_input_stream, user_data);
    return;
  }

  r->content_length += chunk_len;

  g_message("Reading chunk: %ld, %lu", chunk_len, r->content_length);

  if (chunk_len > r->chunk_len || r->chunk == NULL) {
    g_debug("Allocing chunk");
    g_free(r->chunk);
    r->chunk = g_malloc(chunk_len + 1);
  }
  r->chunk_len = chunk_len;

  g_debug("Invoking read (chunk len: %lu)", r->chunk_len);
  g_input_stream_read_all_async(stream, r->chunk, chunk_len, G_PRIORITY_DEFAULT,
                                r->owner->cancel, read_chunked_body, user_data);
}

static void
read_chunked_header(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = HTTP_REQUEST(user_data);
  GBufferedInputStream *stream = G_BUFFERED_INPUT_STREAM(source_object);
  gssize read;

  gsize peek_size;

  const gchar *buffer;
  const gchar *body;
  gssize chunk_len;

  GError *err = NULL;

  g_assert(stream);
  g_assert(res);
  g_assert(r);

  read = g_buffered_input_stream_fill_finish(stream, res, &err);
  if (read < 0) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }
  buffer = g_buffered_input_stream_peek_buffer(stream, &peek_size);
  body = g_strstr_len(buffer + 1, peek_size, CHUNKHEADER_END);

  if (body == NULL) {
    /* chunk headers should be way smaller than our buffer size... */
    g_set_error (&r->error, error_quark(), -1, "Invalid chunk header size");
    return;
  }

  g_message("Chunk length calc: %ld + %ld", body - buffer,
            strlen(CHUNKHEADER_END));

  chunk_len = body - buffer + strlen(CHUNKHEADER_END);

  if (chunk_len > r->chunk_len + 1) {
    g_free(r->chunk);
    r->chunk = g_malloc0(r->chunk_len + 1);
  }
  r->chunk_len = chunk_len + 1;

  g_input_stream_read_all_async(G_INPUT_STREAM(stream), r->chunk, r->chunk_len,
                                G_PRIORITY_DEFAULT, r->owner->cancel,
                                parse_chunked_header, user_data);
}

static void
complete_body_written(GObject *source_object,
                      GAsyncResult *res,
                      gpointer user_data)
{
  GOutputStream *stream = G_OUTPUT_STREAM(source_object);
  HttpRequest *r = HTTP_REQUEST(user_data);
  GError *err = NULL;

  g_assert(stream);
  g_assert(res);
  g_assert(r);

  if (!g_output_stream_write_all_finish(stream, res, NULL, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  request_done(r);
}

static void
read_complete_body(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  GInputStream *stream = G_INPUT_STREAM(source_object);
  HttpRequest *r = HTTP_REQUEST(user_data);
  GError *err = NULL;

  g_assert(stream);
  g_assert(res);
  g_assert(r);

  if (!g_input_stream_read_all_finish(stream, res, NULL, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  g_debug("Read complete body! %ld", r->content_length);

  g_output_stream_write_all_async(r->response, r->chunk, r->chunk_len,
                                  G_PRIORITY_DEFAULT, r->owner->cancel,
                                  complete_body_written, user_data);
}

static void
parse_headers(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  GInputStream *stream = G_INPUT_STREAM(source_object);
  HttpRequest *r = HTTP_REQUEST(user_data);
  gchar **firstline;
  gchar **headers;
  gchar **line;
  gsize header_len;
  GError *err = NULL;

  g_assert(stream);
  g_assert(res);
  g_assert(r);

  if (!g_input_stream_read_all_finish(stream, res, &header_len, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  headers = g_strsplit(r->raw_header, "\r\n", -1);

  if (g_strv_length(headers) < 1) {
    g_set_error (&r->error, error_quark(), -1, "Invalid response from server");
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  firstline = g_strsplit(headers[0], " ", 3);

  if (g_strv_length(firstline) != 3) {
    g_strfreev(firstline);
    g_set_error (&r->error, error_quark(), -1, "Invalid response from server");
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  r->status = g_ascii_strtoll(firstline[1], NULL, 10);

  if (r->status < 100 || r->status > 599) {
    g_strfreev(firstline);
    g_set_error (&r->error, error_quark(), -1, "Invalid response from server");
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);

    return;
  }

  g_strfreev(firstline);
  r->content_length = -1;

  for (gint i = 1; i < g_strv_length(headers); i++) {
    struct header *h;
    if (g_strcmp0(headers[i], "\r\n") == 0) {
      break;
    }
    line = g_strsplit(headers[i], ":", 2);

    if (g_strv_length(line) != 2) {
      g_strfreev(line);
      break;
    }
    gchar *name;
    gchar *val;

    name = g_utf8_strdown(line[0], -1);

    val = g_strdup(line[1]);
    g_strstrip(name);
    g_strstrip(val);

    if (g_strcmp0(name, CONTENT_LENGTH) == 0) {
      r->content_length = g_ascii_strtoll(val, NULL, 10);
    }

    h = g_malloc0(sizeof(*h));
    h->name = name;
    h->value = val;
    r->headers = g_list_append(r->headers, h);

    g_strfreev(line);
    g_debug("Header %s => %s\n", name, val);
  }

  g_strfreev(headers);

  if (r->content_length == 0) {
    request_done(r);
    return;
  }

  if (r->content_length > 0) {
    g_message("Content length: %ld", r->content_length);
    g_free(r->chunk);
    r->chunk = g_malloc0(r->content_length + 1);
    r->chunk_len = r->content_length;

    g_input_stream_read_all_async(stream, r->chunk, r->content_length,
                                  G_PRIORITY_DEFAULT, r->owner->cancel,
                                  read_complete_body, user_data);

  } else {
    g_message("Chunked transfer");
    r->content_length = 0;
    g_buffered_input_stream_fill_async(G_BUFFERED_INPUT_STREAM(stream), -1,
                                       G_PRIORITY_DEFAULT, r->owner->cancel,
                                       read_chunked_header, user_data);
  }

  return;
}

static void
read_headers(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = HTTP_REQUEST(user_data);
  GBufferedInputStream *stream = G_BUFFERED_INPUT_STREAM(source_object);
  gssize read;

  gsize peek_size;
  const gchar *buffer;
  const gchar *body;

  GError *err = NULL;

  g_assert(res);
  g_assert(r);

  read = g_buffered_input_stream_fill_finish(stream, res, &err);

  if (read < 0) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  if (read == 0) {
    r->chunk = g_malloc0(1000);
    gsize re;
    if (!g_input_stream_read_all(G_INPUT_STREAM(stream), r->chunk, 1000, &re,
                                 NULL, &err)) {
      g_warning("ERORR: %s", err->message);
    } else {
      g_debug("READ %lu; %s", re, r->chunk);
    }

    gsize current = g_buffered_input_stream_get_buffer_size(stream);
    if (current > INPUT_BUFFER_SIZE * 5) {
      buffer = g_buffered_input_stream_peek_buffer(stream, &peek_size);
      g_warning("Could not read headers");
      g_debug("\n\n\n ==== Current buffer ====== \nRead %ld, Size: %lu, Peek: "
              "%lu, "
              "Available: "
              "%lu\n%s",
              read, g_buffered_input_stream_get_buffer_size(stream), peek_size,
              g_buffered_input_stream_get_available(stream), buffer);
      return;
    }
    g_buffered_input_stream_set_buffer_size(stream, current + INPUT_BUFFER_SIZE);
    g_buffered_input_stream_fill_async(stream, -1, G_PRIORITY_DEFAULT,
                                       r->owner->cancel, read_headers,
                                       user_data);
    return;
  }

  buffer = g_buffered_input_stream_peek_buffer(stream, &peek_size);
  body = g_strstr_len(buffer, peek_size, HTTPHEADER_END);

  g_debug("\n\n\n ==== Current buffer ====== \nRead %ld, Size: %lu, Available: "
          "%lu\n%s\n\n",
          read, g_buffered_input_stream_get_buffer_size(stream),
          g_buffered_input_stream_get_available(stream), buffer);

  if (body == NULL) {
    if (read == 0) {
      gchar *line = g_malloc0(g_buffered_input_stream_get_available(stream) + 1);
      (void) g_input_stream_read_all(G_INPUT_STREAM(stream), line,
                                     g_buffered_input_stream_get_available(
                                       stream),
                                     NULL, NULL, NULL);
      g_warning("Read zero bytes with available: \"%s\"\n", line);
      return;
    }
    g_warning("Could not find header end");
    gsize current = g_buffered_input_stream_get_buffer_size(stream);
    if (peek_size >= current - INPUT_BUFFER_SIZE) {
      g_buffered_input_stream_set_buffer_size(stream,
                                              current + INPUT_BUFFER_SIZE);
    }
    g_buffered_input_stream_fill_async(stream, -1, G_PRIORITY_DEFAULT,
                                       r->owner->cancel, read_headers,
                                       user_data);
    return;
  }

  r->raw_header_size = body - buffer + strlen(HTTPHEADER_END);
  r->raw_header = g_malloc0(r->raw_header_size + 1);
  g_debug("Reading raw header\n");
  g_input_stream_read_all_async(G_INPUT_STREAM(stream), r->raw_header,
                                r->raw_header_size, G_PRIORITY_DEFAULT,
                                r->owner->cancel, parse_headers, user_data);
}

static void
write_request_done(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = HTTP_REQUEST(user_data);
  GOutputStream *stream = G_OUTPUT_STREAM(source_object);
  GError *err = NULL;

  g_assert(res);
  g_assert(r);

  if (!g_output_stream_write_all_finish(stream, res, NULL, &err)) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }
  g_debug("Writing request done, reading headers\n");

  if (r->owner->input == NULL) {
    g_info("STREAM IS WEIRD\n");
  }

  g_buffered_input_stream_fill_async(G_BUFFERED_INPUT_STREAM(r->owner->input),
                                     -1, G_PRIORITY_DEFAULT, r->owner->cancel,
                                     read_headers, user_data);
}

static gchar *
create_header_str(const gchar *method,
                  const gchar *path,
                  const gchar *query,
                  GList *headers)
{
  GList *l;
  GStrvBuilder *b;
  gchar *line;
  gchar **header_array;
  gchar *res;

  b = g_strv_builder_new();
  line = g_strdup_printf("%s %s%s%s HTTP/1.1", method,
                         strlen(path) > 0 ? path : "/", query ? "?" : "",
                         query ? query : "");

  g_strv_builder_add(b, line);
  g_free(line);

  for (l = headers; l != NULL; l = l->next) {
    struct header *h = (struct header *) l->data;
    line = g_strdup_printf("%s: %s", h->name, h->value);
    g_strv_builder_add(b, line);
    g_free(line);
  }
  g_strv_builder_add(b, "\r\n");
  header_array = g_strv_builder_end(b);
  res = g_strjoinv("\r\n", header_array);
  g_strfreev(header_array);

  return res;
}

static void
init_request(HttpRequest *r)
{
  g_assert(r);

  g_free(r->chunk);
  r->chunk = create_header_str("GET", g_uri_get_path(r->uri),
                               g_uri_get_query(r->uri), r->headers);
  r->chunk_len = strlen(r->chunk);

  g_debug("Writing headers:\n%s\n", r->chunk);

  g_output_stream_write_all_async(r->owner->output, r->chunk, r->chunk_len,
                                  G_PRIORITY_DEFAULT, r->owner->cancel,
                                  write_request_done, r);
}

static void
connection_ready(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r = HTTP_REQUEST(user_data);
  GSocketClient *client = (GSocketClient *) source_object;
  GInputStream *input = NULL;

  GError *err = NULL;

  g_assert(res);
  g_assert(r);

  r->owner->con = g_socket_client_connect_to_host_finish(client, res, &err);

  if (!r->owner->con) {
    g_propagate_error(&r->error, err);
    r->callback(G_OBJECT(r), (GAsyncResult *) r, r->user_data);
    return;
  }

  r->owner->output = g_io_stream_get_output_stream(G_IO_STREAM(r->owner->con));

  input = g_io_stream_get_input_stream(G_IO_STREAM(r->owner->con));
  r->owner->input = g_buffered_input_stream_new_sized(input, INPUT_BUFFER_SIZE);
  g_clear_object(&input);

  init_request(r);
}

gboolean
http_request_header_equal(const struct header *new, const struct header *old)
{
  return g_ascii_strcasecmp(new->name, old->name) == 0;
}

static void
http_request_free_header(struct header *h)
{
  if (h == NULL) {
    return;
  }

  g_free(h->name);
  g_free(h->value);
  g_free(h);
}

static struct header *
copy_header(const struct header *old)
{
  struct header *new;

  g_assert(old);

  new = g_malloc0(sizeof(*new));
  new->name = g_strdup(old->name);
  new->value = g_strdup(old->value);

  return new;
}

void
http_request_set_header(GList **headers,
                        const struct header *new,
                        gboolean replace)
{
  GList *l;

  for (l = *headers; l != NULL; l = l->next) {
    if (http_request_header_equal(new, l->data)) {
      if (replace) {
        http_request_free_header(l->data);
        l->data = copy_header(new);
      } else {
        return;
      }
    }
  }

  *headers = g_list_append(*headers, copy_header(new));
}

void
http_request_do_async(HttpRequest *r,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
  struct header host_header = { 0 };
  gint port;

  g_return_if_fail(r != NULL);
  g_return_if_fail(r->owner != NULL);
  g_return_if_fail(r->uri != NULL);
  r->callback = callback;
  r->user_data = user_data;

  host_header.name = "Host";
  host_header.value = (gchar *) g_uri_get_host(r->uri);
  g_debug("Setting headers!");
  http_request_set_header(&r->headers, &host_header, FALSE);

  host_header.name = "Connection";
  host_header.value = "keep-alive";
  http_request_set_header(&r->headers, &host_header, FALSE);


  if (r->owner->queue != NULL) {
    r->owner->queue = g_list_append(r->owner->queue, r);

    return;
  }

  r->owner->queue = g_list_append(r->owner->queue, r);

  if (r->owner->con == NULL) {
    if (g_strcmp0(g_uri_get_scheme(r->uri), "https") == 0) {
      g_socket_client_set_tls(r->owner->client, TRUE);
      port = 443;
    } else {
      port = 80;
    }

    if (g_uri_get_port(r->uri) > 0) {
      port = g_uri_get_port(r->uri);
    }

    g_debug("Connecting...!");
    g_socket_client_connect_to_host_async(r->owner->client,
                                          g_uri_get_host(r->uri), port,
                                          r->owner->cancel, connection_ready, r);
  } else {
    init_request(r);
  }
}

HttpRequest *
http_request_do_finish(GObject *source, GAsyncResult *result, GError **error)
{
  HttpRequest *r = HTTP_REQUEST(result);

  g_assert(r);

  if (r->error != NULL) {
    g_propagate_error(error, r->error);
    return NULL;
  }

  return r;
}

void
http_request_add_header()
{
}

void
http_request_set_response(HttpRequest *r, GOutputStream *stream)
{
  r->response = g_object_ref(stream);
}

void
http_request_set_post_data(HttpRequest *r, GInputStream *stream)
{
  r->send_data = g_object_ref(stream);
}

HttpClient *
http_client_new()
{
  g_autoptr(HttpClient) instance = g_object_new(HTTP_TYPE_CLIENT, NULL);
  instance->cancel = g_cancellable_new();

  return g_steal_pointer(&instance);
}

static void
clear_conn(gpointer data)
{
  struct conn *c = (struct conn *) data;

  if (c == NULL) {
    return;
  }
  g_io_stream_close(G_IO_STREAM(c->con), NULL, NULL);

  g_debug("CLEARING CONNECTION\n");

  g_clear_object(&c->con);
  g_clear_object(&c->input);
  g_clear_object(&c->output);
}

static void
conn_unref(gpointer c)
{
  if (c == NULL) {
    return;
  }

  g_atomic_rc_box_release_full(c, clear_conn);
}

static void
http_client_init(HttpClient *self)
{
  self->client = g_socket_client_new();
  self->conns = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                      conn_unref);
}

static void
http_client_dispose(GObject *self)
{
  HttpClient *req = HTTP_CLIENT(self);

  g_clear_object(&req->client);
  g_clear_object(&req->cancel);
  g_clear_pointer(&req->conns, g_hash_table_unref);

  G_OBJECT_CLASS(http_client_parent_class)->dispose(self);
}

static void
http_client_finalize(GObject *self)
{
  G_OBJECT_CLASS(http_client_parent_class)->finalize(self);
}

static void
http_client_class_init(HttpClientClass *class)
{
  G_OBJECT_CLASS(class)->dispose = http_client_dispose;
  G_OBJECT_CLASS(class)->finalize = http_client_finalize;
}

HttpRequest *
http_request_new(HttpClient *client, const gchar *url, GError **err)
{
  GUri *uri = NULL;
  gchar *key;
  struct conn *c = NULL;
  g_autoptr(HttpRequest) instance = g_object_new(HTTP_TYPE_REQUEST, NULL);

  uri = g_uri_parse(url, 0, err);

  if (uri == NULL) {
    return NULL;
  }
  instance->uri = uri;

  key = g_strdup_printf("%s%s%d", g_uri_get_scheme(uri), g_uri_get_scheme(uri),
                        g_uri_get_port(uri));

  c = g_hash_table_lookup(client->conns, key);

  if (c == NULL) {
    c = g_atomic_rc_box_alloc0(sizeof(*c));
    c->cancel = g_object_ref(client->cancel);
    c->client = g_object_ref(client->client);
    c->queue = NULL;
    c->debug = "HELLO";
    g_debug("Request created \n");

    g_hash_table_insert(client->conns, key, c);

  } else {
    g_atomic_rc_box_acquire(c);
    g_free(key);
    g_debug("USING EXISTING CONNECTION\n");
  }
  instance->owner = c;

  return g_steal_pointer(&instance);
}

static void
http_request_init(HttpRequest *self)
{
}

static void
http_request_dispose(GObject *self)
{
  HttpRequest *req = HTTP_REQUEST(self);

  g_clear_object(&req->uri);
  g_clear_pointer(&req->owner, conn_unref);

  G_OBJECT_CLASS(http_request_parent_class)->dispose(self);
}

static void
http_request_finalize(GObject *self)
{
  G_OBJECT_CLASS(http_request_parent_class)->finalize(self);
}

static void
http_request_class_init(HttpRequestClass *class)
{
  G_OBJECT_CLASS(class)->dispose = http_request_dispose;
  G_OBJECT_CLASS(class)->finalize = http_request_finalize;
}
