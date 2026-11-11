import { AppError } from '../core/errors/AppError.js';
import { ErrorCodes } from '../core/errors/errorCodes.js';

/**
 * Zod Schema Validation Factory Middleware
 *
 * @param {import('zod').ZodSchema} schema - The Zod schema to validate against
 * @param {'body' | 'query' | 'params'} source - The request property to validate
 */
export function validate(schema, source = 'body') {
  return async (req, res, next) => {
    try {
      const dataToValidate = req[source];
      const parsedData = await schema.parseAsync(dataToValidate);

      // Replace source with validated, sanitized, and typed data
      req[source] = parsedData;
      next();
    } catch (error) {
      if (error.errors && Array.isArray(error.errors)) {
        const formattedDetails = error.errors.map((err) => ({
          field: err.path.join('.'),
          message: err.message,
          rule: err.code,
        }));

        return next(
          new AppError(
            'Request payload failed strict validation rules',
            400,
            ErrorCodes.VALIDATION_ERROR,
            formattedDetails
          )
        );
      }

      next(error);
    }
  };
}
