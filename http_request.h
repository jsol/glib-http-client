#include <gio/gio.h>
#include <glib.h>
#include <stdio.h>
#include <sysexits.h>

#define HTTP_TYPE_CLIENT  http_client_get_type()
#define HTTP_TYPE_REQUEST http_request_get_type()

G_DECLARE_FINAL_TYPE(HttpClient, http_client, HTTP, CLIENT, GObject)
G_DECLARE_FINAL_TYPE(HttpRequest, http_request, HTTP, REQUEST, GObject)

HttpClient *http_client_new(void);

void http_request_do_async(HttpRequest *self,
                           GAsyncReadyCallback callback,
                           gpointer user_data);

HttpRequest *http_request_do_finish(GObject *source,
                                    GAsyncResult *result,
                                    GError **error);

HttpRequest *http_request_new(HttpClient *client, const gchar *url, GError **err);

void http_request_add_header();

void http_request_set_response(HttpRequest *r, GOutputStream *stream);

void http_request_set_post_data(HttpRequest *r, GInputStream *stream);