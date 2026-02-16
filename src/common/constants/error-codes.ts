/**
 * Catálogo central de códigos de error para respuestas RFC 7807.
 * Usar siempre estas constantes en lugar de strings literales.
 */
export enum ErrorCode {
  BAD_REQUEST = 'BAD_REQUEST',
  AUTH_UNAUTHORIZED = 'AUTH_UNAUTHORIZED',
  AUTH_TOKEN_REVOKED = 'AUTH_TOKEN_REVOKED',
  AUTH_FORBIDDEN = 'AUTH_FORBIDDEN',
  NOT_FOUND = 'NOT_FOUND',
  CONFLICT = 'CONFLICT',
  CONFLICT_DUPLICATE = 'CONFLICT_DUPLICATE',
  UNPROCESSABLE_ENTITY = 'UNPROCESSABLE_ENTITY',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  MESSAGING_SERVICE_ERROR = 'MESSAGING_SERVICE_ERROR',
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
}

/** Mapeo de código HTTP a ErrorCode por defecto (cuando la excepción no trae errorCode). */
export const STATUS_TO_ERROR_CODE: Record<number, ErrorCode> = {
  400: ErrorCode.BAD_REQUEST,
  401: ErrorCode.AUTH_UNAUTHORIZED,
  403: ErrorCode.AUTH_FORBIDDEN,
  404: ErrorCode.NOT_FOUND,
  409: ErrorCode.CONFLICT,
  422: ErrorCode.UNPROCESSABLE_ENTITY,
  429: ErrorCode.RATE_LIMIT_EXCEEDED,
  500: ErrorCode.INTERNAL_SERVER_ERROR,
};
