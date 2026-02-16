import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

/** Mensaje genérico para errores 500: no exponer detalles internos al cliente. */
const GENERIC_500_MESSAGE =
  'Ocurrió un error interno en el servidor';

/** Mapeo de códigos HTTP a slugs de error en mayúsculas. */
const STATUS_TO_ERROR_CODE: Record<number, string> = {
  [HttpStatus.BAD_REQUEST]: 'BAD_REQUEST',
  [HttpStatus.UNAUTHORIZED]: 'AUTH_UNAUTHORIZED',
  [HttpStatus.FORBIDDEN]: 'FORBIDDEN',
  [HttpStatus.NOT_FOUND]: 'NOT_FOUND',
  [HttpStatus.CONFLICT]: 'CONFLICT',
  [HttpStatus.UNPROCESSABLE_ENTITY]: 'UNPROCESSABLE_ENTITY',
  [HttpStatus.TOO_MANY_REQUESTS]: 'RATE_LIMIT_EXCEEDED',
  [HttpStatus.INTERNAL_SERVER_ERROR]: 'INTERNAL_SERVER_ERROR',
};

export interface Rfc7807ErrorBody {
  success: false;
  statusCode: number;
  errorCode: string;
  message: string;
  path: string;
  timestamp: string;
  requestId: string;
}

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const requestId = request.requestId ?? 'unknown';
    const path = request.url ?? request.path ?? '/';
    const timestamp = new Date().toISOString();

    let statusCode: number;
    let message: string;
    let errorCode: string;

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      const res = exception.getResponse();

      if (typeof res === 'object' && res !== null) {
        const obj = res as Record<string, unknown>;
        message = (obj.message as string) ?? exception.message;
        errorCode =
          typeof obj.errorCode === 'string'
            ? (obj.errorCode as string).toUpperCase().replace(/\s+/g, '_')
            : STATUS_TO_ERROR_CODE[statusCode] ?? 'UNKNOWN_ERROR';
      } else {
        message = typeof res === 'string' ? res : exception.message;
        errorCode = STATUS_TO_ERROR_CODE[statusCode] ?? 'UNKNOWN_ERROR';
      }
    } else {
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
      errorCode = 'INTERNAL_SERVER_ERROR';
      message = GENERIC_500_MESSAGE;
    }

    if (statusCode >= 500) {
      message = GENERIC_500_MESSAGE;
      const err = exception instanceof Error ? exception : new Error(String(exception));
      this.logger.error(
        `[requestId=${requestId}] Internal error: ${err.message}`,
        err.stack,
      );
    }

    const body: Rfc7807ErrorBody = {
      success: false,
      statusCode,
      errorCode,
      message,
      path,
      timestamp,
      requestId,
    };

    response.setHeader('X-Request-ID', requestId);
    response.status(statusCode).json(body);
  }
}
