import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  ConflictException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { ErrorCode } from '../constants/error-codes';

const PRISMA_UNIQUE_VIOLATION = 'P2002';
const PRISMA_RECORD_NOT_FOUND = 'P2025';

/**
 * Filtro que captura PrismaClientKnownRequestError y convierte códigos
 * conocidos en excepciones HTTP con ErrorCode. Debe registrarse antes del
 * HttpExceptionFilter para que las excepciones relanzadas sean normalizadas.
 */
@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaClientExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(PrismaClientExceptionFilter.name);

  catch(exception: Prisma.PrismaClientKnownRequestError, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<{ requestId?: string }>();
    const requestId = request.requestId ?? 'unknown';

    const code = exception.code;

    if (code === PRISMA_UNIQUE_VIOLATION) {
      this.logger.warn(
        `[requestId=${requestId}] Prisma P2002 → 409 Conflict. Meta: ${JSON.stringify(exception.meta)}`,
      );
      throw new ConflictException({
        message: 'El recurso ya existe (violación de unicidad).',
        errorCode: ErrorCode.CONFLICT_DUPLICATE,
      });
    }

    if (code === PRISMA_RECORD_NOT_FOUND) {
      this.logger.warn(
        `[requestId=${requestId}] Prisma P2025 → 404 Not Found. Meta: ${JSON.stringify(exception.meta)}`,
      );
      throw new NotFoundException({
        message: 'El registro solicitado no fue encontrado.',
        errorCode: ErrorCode.NOT_FOUND,
      });
    }

    // Resto de códigos Prisma: no convertimos; dejamos que el filtro global devuelva 500
    this.logger.error(
      `[requestId=${requestId}] Prisma error no mapeado: ${code}. ${exception.message}`,
      exception.stack,
    );
    throw exception;
  }
}
