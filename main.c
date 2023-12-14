#include <gio/gio.h>
#include <glib.h>
#include <stdio.h>
#include <sysexits.h>

#include "http_request.h"

/** Program options */
struct prog_options {
  gchar *api_key;
  gchar *secret_key;
  gchar *path;
};

static gboolean
parse_prog_options(struct prog_options *opts,
                   int *argc,
                   char ***argv,
                   GError **err)
{
  GOptionContext *opt_ctx;
  gboolean ret = FALSE;
  GOptionEntry opt_ents[] = { { "api-key", 'a', 0, G_OPTION_ARG_STRING,
                                &opts->api_key, "S3 API key", NULL },
                              { "secret-key", 's', 0, G_OPTION_ARG_STRING,
                                &opts->secret_key, "S3 Secret key", NULL },
                              { "path", 'p', 0, G_OPTION_ARG_STRING,
                                &opts->path, "File path to upload", NULL },
                              { NULL } };

  g_assert(opts);
  g_assert(argc);
  g_assert(argv);
  g_assert(err == NULL || *err == NULL);

  opt_ctx = g_option_context_new(NULL);

  g_option_context_add_main_entries(opt_ctx, opt_ents, NULL);
  if (!g_option_context_parse(opt_ctx, argc, argv, err)) {
    goto out;
  }

  ret = TRUE;

/* Fall through */
out:
  g_option_context_free(opt_ctx);

  return ret;
}

static void
clear_prog_options(struct prog_options *opts)
{
  g_assert(opts);

  g_free(opts->api_key);
  g_free(opts->secret_key);
  g_free(opts->path);

  memset(opts, 0, sizeof(*opts));
}

void
req_cb(GObject *source, GAsyncResult *res, gpointer user_data)
{
  HttpRequest *r;
  GMemoryOutputStream *body = G_MEMORY_OUTPUT_STREAM(user_data);
  GError *err = NULL;

  r = http_request_do_finish(source, res, &err);

  if (r == NULL) {
    g_warning("Error during request: %s", err->message);
    return;
  }

  if (user_data != NULL) {
    gsize len = g_memory_output_stream_get_data_size(body);
    gchar *b = (gchar *) g_memory_output_stream_steal_data(body);
    /* TODO NULL terminate? Should we do this in the request? */
    b[len - 1] = '\0';
    //g_print("Result: %s", b);
    /* TODO use free function from g_memory*/
    g_free(b);
  }

  //  g_clear_object(&r);
}

int
main(int argc, char *argv[])
{
  struct prog_options opts = { 0 };
  HttpClient *client = NULL;
  HttpRequest *req = NULL;
  GMainLoop *loop = NULL;
  GError *err = NULL;
  gint ret_val = 0;
  GOutputStream *body = NULL;

  if (!parse_prog_options(&opts, &argc, &argv, &err)) {
    g_warning("Failed to parse app options: %s", err->message);
    g_clear_error(&err);
    goto exit;
  }

  loop = g_main_loop_new(NULL, FALSE);

  client = http_client_new();

  req = http_request_new(client, "https://www.rootsy.nu", &err);

  if (req == NULL) {
    g_warning("Error creating request: %s", err->message);
    g_clear_error(&err);
  }
  body = g_memory_output_stream_new_resizable();
  http_request_set_response(req, body);
  http_request_do_async(req, req_cb, body);

  req = http_request_new(client, "https://www.rootsy.nu", &err);

  if (req == NULL) {
    g_warning("Error creating request: %s", err->message);
    g_clear_error(&err);
  }
  body = g_memory_output_stream_new_resizable();
  http_request_set_response(req, body);
  http_request_do_async(req, req_cb, body);

  g_main_loop_run(loop);

exit:
  clear_prog_options(&opts);

  return ret_val;
}
