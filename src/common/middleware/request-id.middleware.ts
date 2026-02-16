import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

/**
 * Middleware que asigna un X-Request-ID único a cada petición.
 * Si el cliente envía X-Request-ID, se reutiliza para trazabilidad distribuida.
 * El ID se almacena en req.requestId y debe incluirse en respuestas (header + body de errores).
 */
@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction): void {
    const incomingId = req.headers['x-request-id'];
    req.requestId =
      typeof incomingId === 'string' ? incomingId : randomUUID();
    next();
  }
}
