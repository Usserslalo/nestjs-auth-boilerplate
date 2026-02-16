import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

/**
 * Interceptor opcional para logging de peticiones evaluadas por Throttler.
 * Desactivar en producción si genera ruido.
 */
@Injectable()
export class ThrottlerLoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      tap(() => {
        // Petición pasó el Throttler y el handler
      }),
    );
  }
}
