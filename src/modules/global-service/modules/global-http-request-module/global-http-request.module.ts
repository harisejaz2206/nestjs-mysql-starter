import { Module } from '@nestjs/common';
import { GlobalHttpRequestService } from './global-http-request.service';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [HttpModule],
  providers: [GlobalHttpRequestService],
  exports: [GlobalHttpRequestService],
})
export class GlobalHttpRequestModule {}
