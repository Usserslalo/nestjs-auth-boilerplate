import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { ErrorCode, STATUS_TO_ERROR_CODE } from '../constants/error-codes';

/** Mensaje genérico para errores 500: no exponer detalles internos al cliente. */
const GENERIC_500_MESSAGE =
  'Ocurrió un error interno en el servidor';

export interface Rfc7807ErrorBody {
  success: false;
  statusCode: number;
  errorCode: string;
  message: string;
  path: string;
  timestamp: string;
  requestId: string;
  /** Detalle por campo (errores de validación DTO). Solo presente cuando message es un resumen de varios. */
  errors?: string[];
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
    let errors: string[] | undefined;

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      const res = exception.getResponse();

      if (typeof res === 'object' && res !== null) {
        const obj = res as Record<string, unknown>;
        const rawMessage = obj.message;

        if (Array.isArray(rawMessage)) {
          const arr = rawMessage as string[];
          message = arr.join('; ');
          errors = arr;
        } else {
          message = (rawMessage as string) ?? exception.message;
        }

        errorCode =
          typeof obj.errorCode === 'string'
            ? (String(obj.errorCode)).toUpperCase().replace(/\s+/g, '_')
            : (STATUS_TO_ERROR_CODE[statusCode] ?? ErrorCode.UNKNOWN_ERROR);
      } else {
        message = typeof res === 'string' ? res : exception.message;
        errorCode = STATUS_TO_ERROR_CODE[statusCode] ?? ErrorCode.UNKNOWN_ERROR;
      }
    } else {
      statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
      errorCode = ErrorCode.INTERNAL_SERVER_ERROR;
      message = GENERIC_500_MESSAGE;
    }

    if (statusCode >= 500) {
      message = GENERIC_500_MESSAGE;
      const err = exception instanceof Error ? exception : new Error(String(exception));
      this.logger.error(
        `[requestId=${requestId}] Internal error: ${err.message}`,
        err.stack,
      );
    } else {
      this.logger.warn(
        `[requestId=${requestId}] path=${path} statusCode=${statusCode} errorCode=${errorCode}`,
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
    if (errors !== undefined) {
      body.errors = errors;
    }

    response.setHeader('X-Request-ID', requestId);

    if (statusCode === HttpStatus.TOO_MANY_REQUESTS) {
      const retryAfterSec = parseRetryAfterSeconds(message);
      response.setHeader('Retry-After', String(retryAfterSec));
    }

    response.status(statusCode).json(body);
  }
}

/**
 * Extrae segundos de espera del mensaje de error (ej. "Espere 120 segundos..." o "Too Many Requests").
 * Usado para el header Retry-After en respuestas 429.
 */
function parseRetryAfterSeconds(message: string): number {
  const match = message.match(/(\d+)\s*(?:segundos?|seconds?)?/i) ?? message.match(/(\d+)/);
  if (match) {
    const sec = parseInt(match[1], 10);
    return Number.isFinite(sec) && sec > 0 ? Math.min(sec, 3600) : 60;
  }
  return 60;
}
