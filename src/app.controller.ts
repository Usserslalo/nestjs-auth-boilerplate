import { Controller, Get } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Public } from './common/decorators';
import { AppService } from './app.service';

@ApiTags('Raíz')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Public()
  @ApiOperation({
    summary: 'Health check / Bienvenida',
    description: 'Ruta raíz pública que devuelve un mensaje de bienvenida. Útil para comprobar que la API está en marcha.',
  })
  @ApiResponse({
    status: 200,
    description: 'Servidor en funcionamiento.',
    schema: { type: 'string', example: 'Hello World!' },
  })
  getHello(): string {
    return this.appService.getHello();
  }
}
