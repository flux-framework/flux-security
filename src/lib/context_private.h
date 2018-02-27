#ifndef _FLUX_SECURITY_CONTEXT_PRIVATE_H
#define _FLUX_SECURITY_CONTEXT_PRIVATE_H

#include <stdarg.h>
#include "src/libutil/cf.h"

/* Capture errno in ctx->errno, and an error message in ctx->error.
 * If 'fmt' is non-NULL, build message; otherwise use strerror (errno).
 */
void security_error (flux_security_t *ctx, const char *fmt, ...);

/* Retrieve config object by 'key'.
 * Returns the object (do not free), or NULL on error.
 */
const cf_t *security_get_config (flux_security_t *ctx, const char *key);

#endif /* !_FLUX_SECURITY_CONTEXT_PRIVATE_H */