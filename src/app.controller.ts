import { Get, HttpStatus } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiController } from './modules/globals/decorators/global.decorators';
import { GlobalResponseDto } from './modules/globals/dtos/global.response.dto';

@ApiController({
  prefix: '/app',
  tagName: 'App',
  isBearerAuth: false,
})
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('hello')
  getHello() {
    return new GlobalResponseDto(HttpStatus.OK, 'App', 'Hello, World!');
  }
}
