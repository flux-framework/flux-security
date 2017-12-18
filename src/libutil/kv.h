#ifndef _UTIL_KV_H
#define _UTIL_KV_H

/* Simple serialization:
 *   key=value\0key=value\0...key=value\0
 */

#include <stdarg.h>
#include <stdbool.h>

#define KV_MAX_KEY 128

typedef char kv_keybuf_t[KV_MAX_KEY + 1];

/* Create/destroy/copy kv object.
 */
struct kv *kv_create (void);
void kv_destroy (struct kv *kv);
struct kv *kv_copy (const struct kv *kv);

/* Return true if kv1 is identical to kv2 (including entry order)
 */
bool kv_equal (const struct kv *kv1, const struct kv *kv2);

/* Remove 'key' from kv object.
 *   EINVAL - invalid argument
 *   ENOENT - key not found
 */
int kv_delete (struct kv *kv, const char *key);

/* Add key=val to kv object.
 * Return 0 on success, -1 on failure with errno set:
 *   EINVAL - invalid argument
 *   ENOMEM - out of memory
 */
int kv_put (struct kv *kv, const char *key, const char *val);

/* Find key in kv object and set val (if 'val' is non-NULL).
 * Return 0 on success, -1 on failure wtih errno set:
 *   EINVAL - invalid argument
 *   ENOENT - key not found
 */
int kv_get (const struct kv *kv, const char *key, const char **val);

/* Convenience wrapper for kv_put with printf-style args for value.
 * Return 0 on success, -1 on failure with errno set:
 *   EINVAL - invalid argument / sscanf problem
 *   ENOENT - key not found
 *   ENOMEM - out of memory
 */
int kv_putf (struct kv *kv, const char *key, const char *fmt, ...)
        __attribute__ ((format (printf, 3, 4)));

/* Convenience wrapper for kv_get with scanf-style args for value.
 * Return number of matches on success, -1 on failure wtih errno set:
 *   EINVAL - invalid argument
 *   ENOENT - key not found
 */
int kv_getf (const struct kv *kv, const char *key, const char *fmt, ...)
        __attribute__ ((format (scanf, 3, 4)));

/* Encode kv object as NULL-terminated base64 string (do not free).
 * String remains valid until the next call to kv_base64_encode()
 * or kv_destroy().  Return NULL-terminated base64 string on success,
 * NULL on failure with errno set.
 */
const char *kv_base64_encode (const struct kv *kv);

/* Decode base64 string to kv object (destroy with kv_destroy).
 * Return kv object on success, NULL on failure with errno set.
 */
struct kv *kv_base64_decode (const char *s, int len);

/* Access internal binary encoding.
 * Return 0 on success, -1 on failure with errno set.
 */
int kv_raw_encode (const struct kv *kv, const char **buf, int *len);

/* Create kv object from binary encoding.
 * Return kv object on success, NULL on failure with errno set.
 */
struct kv *kv_raw_decode (const char *buf, int len);

/* Iteration example:
 *
 *   const char *entry;
 *   kv_keybuf_t keybuf;
 *
 *   entry = kv_entry_first (kv);
 *   while (entry) {
 *       const char *key = kv_entry_key (entry, keybuf);
 *       const char *val = kv_entry_val (entry);
 *       ...
 *       entry = kv_entry_next (kv, entry);
 *   }
 *
 * N.B. the object may not be changed during iteration.
 */
const char *kv_entry_first (const struct kv *kv);
const char *kv_entry_next (const struct kv *kv, const char *entry);
const char *kv_entry_key (const char *entry, kv_keybuf_t keybuf);
const char *kv_entry_val (const char *entry);

#endif /* !_UTIL_KV_H */

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */
