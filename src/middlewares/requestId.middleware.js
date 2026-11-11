import crypto from 'node:crypto';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Correlation ID (X-Request-Id) Middleware
 * Ensures every incoming request has a unique identifier for distributed tracing and log correlation.
 */
export function requestIdMiddleware(req, res, next) {
  const incomingRequestId = req.headers['x-request-id'];

  // Accept incoming request ID only if it is a valid UUID format (avoids header injection or malformed values)
  const requestId = (incomingRequestId && UUID_REGEX.test(incomingRequestId))
    ? incomingRequestId
    : crypto.randomUUID();

  req.id = requestId;
  res.setHeader('X-Request-Id', requestId);
  next();
}
