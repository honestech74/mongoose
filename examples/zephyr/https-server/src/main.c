// Copyright (c) 2020 Cesanta Software Limited
// All rights reserved

#include "mongoose.h"
#include "server_pem.h"
#include "server_key_pem.h"
#include <logging/log.h>
LOG_MODULE_REGISTER(webserver, CONFIG_LOG_DEFAULT_LEVEL);

static const char *s_debug_level = "3";
static const char *s_root_dir = ".";
static const char *s_listening_address = "https://0.0.0.0:443";
static time_t s_boot_timestamp = 0;
static struct mg_connection *s_sntp_conn = NULL;

#define CERT_FILENAME     "server.pem"
#define CERT_KEY_FILENAME "server-key.pem"

typedef struct embedded_file_t {
  const char *filename;
  uint8_t *data;
  uint32_t size;
} embedded_file_t;

#define EMBEDDED_FS_FILE_SIZE (2)
embedded_file_t embedded_fs_files[EMBEDDED_FS_FILE_SIZE];

void init_embedded_fs(void) {
  embedded_fs_files[0].filename = "server.pem";
  embedded_fs_files[0].data     = server_pem;
  embedded_fs_files[0].size     = server_pem_len;
  embedded_fs_files[1].filename = "server-key.pem";
  embedded_fs_files[1].data     = server_key_pem;
  embedded_fs_files[1].size     = server_key_pem_len;
}

int get_embedded_file_index(const char *path) {
  for (int i = 0; i < EMBEDDED_FS_FILE_SIZE; i++) {
    if (strcmp(path, embedded_fs_files[i].filename) == 0) {
      return i;
    }
  }
  return -1;
}

struct embedded_file {
  const char *data;
  size_t size;
  size_t pos;
};

static int embedded_stat(const char *path, size_t *size, time_t *mtime) {
  int index = get_embedded_file_index(path);
  if (index >= 0) {
    *size = embedded_fs_files[index].size;
    return 0;
  }
  return -EINVAL;
}

static void embedded_list(const char *dir, void (*fn)(const char *, void *),
                        void *userdata) {
  (void) dir, (void) fn, (void) userdata;
}

static void *embedded_open(const char *path, int flags) {
  struct embedded_file *fp = NULL;
  int index = get_embedded_file_index(path);
  if (index < 0) return fp;
  fp = (struct embedded_file *) calloc(1, sizeof(*fp));
  fp->size = embedded_fs_files[index].size;
  fp->data = embedded_fs_files[index].data;
  return (void *) fp;
}

static void embedded_close(void *fp) {
  if (fp != NULL) free(fp);
}

static size_t embedded_read(void *fd, void *buf, size_t len) {
  struct embedded_file *fp = (struct embedded_file *) fd;
  if (fp->pos + len > fp->size) len = fp->size - fp->pos;
  memcpy(buf, &fp->data[fp->pos], len);
  fp->pos += len;
  return len;
}

static size_t embedded_write(void *fd, const void *buf, size_t len) {
  (void) fd, (void) buf, (void) len;
  return 0;
}

static size_t embedded_seek(void *fd, size_t offset) {
  struct embedded_file *fp = (struct embedded_file *) fd;
  fp->pos = offset;
  if (fp->pos > fp->size) fp->pos = fp->size;
  return fp->pos;
}

static bool embedded_rename(const char *from, const char *to) {
  (void) from, (void) to;
  return false;
}

static bool embedded_remove(const char *path) {
  (void) path;
  return false;
}

static bool embedded_mkdir(const char *path) {
  (void) path;
  return false;
}

struct mg_fs mg_fs_embeded = {
    embedded_stat,  embedded_list, embedded_open,   embedded_close,  embedded_read,
    embedded_write, embedded_seek, embedded_rename, embedded_remove, embedded_mkdir};

// Event handler for the listening connection.
// Simply serve static files from `s_root_dir`
static void cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_ACCEPT) {
    struct mg_tls_opts opts = {
        .cert = CERT_FILENAME,     // Certificate PEM file
        .certkey = CERT_KEY_FILENAME,  // This pem contains both cert and key
        .fs = &mg_fs_embeded,
    };
    mg_tls_init(c, &opts);
  }
  else if (ev == MG_EV_HTTP_MSG)
  {
      struct mg_http_message *hm = (struct mg_http_message *) ev_data;

      // Test API
      if (mg_http_match_uri(hm, "/api/test/set/*")) {
          uint8_t val = atoi(hm->uri.ptr + strlen("/api/test/set/"));
          LOG_DBG("air_flow uri val: %.*s, parsed val: %d", (int)hm->uri.len, hm->uri.ptr, val);
          mg_printf(c, "%s", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
      } else if (mg_http_match_uri(hm, "/api/test/get")) {
          mg_http_reply(c, 200, "", "{\"result\": \"%d\"}\n", 1);
      } else {
        mg_http_reply(c, 200, NULL, "hi\n");
      }
  } else if (ev == MG_EV_OPEN) {
    c->is_hexdumping = 1;
  }
  (void) fn_data;
}

// We have no valid system time(), and we need it for TLS. Implement it
time_t time(time_t *tp) {
  time_t t = s_boot_timestamp + k_uptime_get() / 1000;
  if (tp != NULL) *tp = t;
  return t;
}

static void sfn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_SNTP_TIME) {
    int64_t t = *(int64_t *) ev_data;
    MG_INFO(("Got SNTP time: %lld ms from epoch", t));
    s_boot_timestamp = (time_t) ((t - mg_millis()) / 1000);
  } else if (ev == MG_EV_CLOSE) {
    s_sntp_conn = NULL;
  }
}

static void timer_fn(void *arg) {
  struct mg_mgr *mgr = (struct mg_mgr *) arg;
  return;
  if (s_sntp_conn == NULL) s_sntp_conn = mg_sntp_connect(mgr, NULL, sfn, NULL);
  if (s_boot_timestamp < 9999) mg_sntp_send(s_sntp_conn, time(NULL));
}

static void logfn(const void *ptr, size_t len, void *userdata) {
  printk("%.*s", (int) len, (char *) ptr);
}

int main(int argc, char *argv[]) {
  struct mg_mgr mgr;

  init_embedded_fs();

  mg_log_set(s_debug_level);
  mg_log_set_callback(logfn, NULL);

  mg_mgr_init(&mgr);
  mg_http_listen(&mgr, s_listening_address, cb, &mgr);

  // struct mg_timer t;
  // mg_timer_init(&t, 5000, MG_TIMER_REPEAT | MG_TIMER_RUN_NOW, timer_fn, &mgr);

  // Start infinite event loop
  MG_INFO(("Mongoose version : v%s", MG_VERSION));
  MG_INFO(("Listening on     : %s", s_listening_address));
  MG_INFO(("Web root         : [%s]", s_root_dir));
  for (;;) mg_mgr_poll(&mgr, 1000);
  mg_mgr_free(&mgr);
  return 0;
}
