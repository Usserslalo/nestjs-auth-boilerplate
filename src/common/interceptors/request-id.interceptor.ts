import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

/**
 * Interceptor que añade el header X-Request-ID a todas las respuestas exitosas.
 * El requestId se asigna en RequestIdMiddleware y se incluye en respuestas de error
 * por HttpExceptionFilter; aquí se asegura que también aparezca en respuestas 2xx.
 */
@Injectable()
export class RequestIdInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const httpCtx = context.switchToHttp();
    const request = httpCtx.getRequest<{ requestId?: string }>();
    const response = httpCtx.getResponse<{ setHeader: (k: string, v: string) => void }>();

    return next.handle().pipe(
      tap(() => {
        const id = request.requestId;
        if (id) {
          response.setHeader('X-Request-ID', id);
        }
      }),
    );
  }
}
