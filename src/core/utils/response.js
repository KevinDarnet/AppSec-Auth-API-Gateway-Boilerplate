/**
 * Standardized API Response Envelope
 * Ensures all responses adhere to a consistent, predictable contract.
 */
export class ApiResponse {
  static success(res, data = null, message = 'Success', statusCode = 200, meta = {}) {
    return res.status(statusCode).json({
      success: true,
      statusCode,
      message,
      data,
      meta: {
        timestamp: new Date().toISOString(),
        requestId: res.getHeader('X-Request-Id') || undefined,
        ...meta,
      },
    });
  }

  static error(res, message = 'Internal Server Error', statusCode = 500, errorCode = 'INTERNAL_ERROR', details = null, meta = {}) {
    return res.status(statusCode).json({
      success: false,
      statusCode,
      message,
      error: {
        code: errorCode,
        details: details || undefined,
      },
      meta: {
        timestamp: new Date().toISOString(),
        requestId: res.getHeader('X-Request-Id') || undefined,
        ...meta,
      },
    });
  }
}
