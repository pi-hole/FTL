// SPDX-License-Identifier: BSD-3-Clause

#ifndef JOURNAL_H
#define JOURNAL_H

#include <sys/syslog.h>
#include <sys/uio.h>

#define LIBJOURNAL_VERSION "0.1"

/* Call early (e.g. during flag parsing) to detect missing journald and enable
 * early exits. Safe to call multiple times; returns immediately if already connected. */
int journal_init(void);

/* Close the journal socket. Not thread-safe when combined with other methods;
 * intended for valgrind/gdb cleanup only. Letting it close on exit is fine. */
void journal_close(void);

/* Return the current journal socket fd, or -1 if not connected.
 * Useful for polling, but callers should not assume the fd remains
 * stable across send operations because the library may reconnect. */
int journal_get_fd(void) __attribute__((pure));

/* Log a formatted message with syslog-style priority. Convenience wrapper that
 * sets MESSAGE and PRIORITY fields automatically. */
int journal_print(int priority, const char *format, ...) __attribute__((format(printf, 2, 3)));

/* Send structured journal fields as key=value pairs, NULL-terminated.
 * Field values may contain printf-style conversions. Invalid keys are silently
 * skipped. Trailing whitespace in values is trimmed. Values containing
 * NUL or newline bytes are sent as binary automatically. */
int journal_send(const char *format, ...) __attribute__((format(printf, 1, 0)))
__attribute__((sentinel));

/* Send pre-formatted journal fields via iovec. Each entry must contain one
 * complete field in the format "KEY=value\n". Binary fields must already be
 * encoded using journald's binary field format. Large payloads (>128 KB) are
 * sent via memfd automatically. */
int journal_sendv(const struct iovec *iov, int n);

#endif
