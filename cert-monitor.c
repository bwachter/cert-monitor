/**
 * @file cert-monitor.c
 * @copyright GPLv3
 * @author Bernd Wachter <bernd-github@wachter.fi>
 * @date 2016
 *
 * DBus connection is based on the tutorial from
 * http://www.matthew.ath.cx/misc/dbus
 */

#include <sys/inotify.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <libgen.h>
#include <string.h>
#include <fcntl.h>
#include <dbus/dbus.h>
#include <systemd/sd-journal.h>

#define CFG_DIR "/etc/cert-monitor.d"

DBusConnection *conn;

// try to restart a systemd service
// if anything goes wrong service restart will just be skipped (i.e.,
// your service might be running with outdated certificates)
// TODO: record errors and try again later
void restart_service(char *service, char *startmode){
  DBusMessage* msg;
  DBusMessageIter args;
  DBusPendingCall* pending;
  char* stat;

  msg = dbus_message_new_method_call
    ("org.freedesktop.systemd1", // target for the method call
     "/org/freedesktop/systemd1", // object to call on
     "org.freedesktop.systemd1.Manager", // interface to call on
     "RestartUnit"); // method name

  if (msg == NULL) {
    sd_journal_print(LOG_ERR,
                     "DBus message creation failed, skipping restart of '%s'",
                     service);
    return;
  }

  // append arguments
  dbus_message_iter_init_append(msg, &args);
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &service)) {
    sd_journal_print(LOG_ERR,
                     "OOM when creating DBus message, skipping restart of '%s'",
                     service);
    return;
  }
  if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &startmode)) {
    sd_journal_print(LOG_ERR,
                     "OOM when creating DBus message, skipping restart of '%s'",
                     service);
    return;
  }

  // send message and get a handle for a reply
  if (!dbus_connection_send_with_reply (conn, msg, &pending, -1)) { // -1 is default timeout
    sd_journal_print(LOG_ERR,
                     "OOM when sending DBus message, skipping restart of '%s'",
                     service);
    return;
  }
  if (pending == NULL) {
    sd_journal_print(LOG_ERR,
                     "DBus call pending is NULL, skipping restart of '%s'",
                     service);
    return;
  }
  dbus_connection_flush(conn);

  // free message
  dbus_message_unref(msg);

  // block until we receive a reply
  dbus_pending_call_block(pending);

  // get the reply message
  msg = dbus_pending_call_steal_reply(pending);
  if (msg == NULL) {
    sd_journal_print(LOG_ERR,
                     "DBus reply is NULL, skipping restart of '%s'",
                     service);
    return;
  }
  // free the pending message handle
  dbus_pending_call_unref(pending);

  // read the parameters
  if (!dbus_message_iter_init(msg, &args))
    sd_journal_print(LOG_ERR, "Received DBus Message has no arguments.\n");
  else if (DBUS_TYPE_OBJECT_PATH == dbus_message_iter_get_arg_type(&args)) {
    dbus_message_iter_get_basic(&args, &stat);
    sd_journal_print(LOG_INFO, "%s restart job: %s\n", service, stat);
  } else if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args)) {
    dbus_message_iter_get_basic(&args, &stat);
    sd_journal_print(LOG_ERR, "%s restart error: %s\n", service, stat);
  } else
    sd_journal_print(LOG_ERR, "Unexpected argument type: %i\n", dbus_message_iter_get_arg_type(&args));

  // free reply and close connection
  dbus_message_unref(msg);
}

// try to open a directory matching the changed file, and use all
// files in that directory as services to be restarted.
// note that -- depending on configuration -- a service may be restarted
// twice if both key and certificate change.
void handle_event(const char *keyname){
  char buf[PATH_MAX];
  DIR *dir;
  struct dirent *ent;

  snprintf(buf, 512, "%s/%s", CFG_DIR, keyname);

  dir = opendir(buf);
  if (dir == NULL){
    perror(keyname);
    return;
  }

  for (ent=readdir(dir); ent!=NULL; ent=readdir(dir)){
    if (!strncmp(ent->d_name, ".", 1)) continue;
    if (!strncmp(ent->d_name, "..", 2)) continue;

    sd_journal_print(LOG_INFO, "Restarting '%s' for key '%s'\n", ent->d_name, keyname);
    restart_service(ent->d_name, "replace");
  }

  closedir(dir);
}

int main(int argc, char **argv){
  int iFd, wd;
  char buf[12207]
    __attribute__ ((aligned(__alignof__(struct inotify_event))));
  DBusError err;

  dbus_error_init(&err);

  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
  if (dbus_error_is_set(&err)){
    sd_journal_print(LOG_ERR, "Error connecting to DBus: %s", err.message);
    dbus_error_free(&err);
  }
  if (NULL == conn){
    exit(-1);
  }

  if ((iFd = inotify_init()) == -1){
    sd_journal_print(LOG_ERR, "inotify_init() failed");
    exit(-1);
  }

  if ((wd = inotify_add_watch(iFd, "/etc/ssl/keys", IN_CLOSE_WRITE)) == -1){
    sd_journal_print(LOG_ERR, "inotify_add_watch failed on /etc/ssl/keys\n");
    exit(-1);
  }

  for (;;){
    size_t len;
    const struct inotify_event *event;
    char *ptr;

    len = read(iFd, buf, sizeof buf);
    if (len <= 0){
      perror("read");
      exit(-1);
    }

    for (ptr = buf; ptr < buf + len;
         ptr += sizeof(struct inotify_event) + event->len) {

      event = (const struct inotify_event *) ptr;

      if (event->mask & IN_CLOSE_WRITE ||
          event->mask & IN_IGNORED){

        sd_journal_print(LOG_INFO, "Key '%s' changed on disk.\n", event->name);
        handle_event(event->name);

        if (event->mask & IN_IGNORED){
          sd_journal_print(LOG_INFO, "Re-adding inotify watches\n");

          if ((wd = inotify_add_watch(iFd, "/etc/ssl/keys", IN_CLOSE_WRITE)) == -1){
            sd_journal_print(LOG_ERR, "inotify_add_watch failed on /etc/ssl/keys\n");
            exit(-1);
          }
        }
      } else {
        sd_journal_print(LOG_INFO, "Ignored event %i\n", event->mask);
      }
    }
  }
}
