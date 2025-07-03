import { Global, Module } from '@nestjs/common';
import { LoggerService } from './services/logger.service';
import { RequestService } from './services/request.service';
import { GlobalHttpRequestModule } from './modules/global-http-request-module/global-http-request.module';
import { EmailService } from './services/email.service';
import { AsposeService } from './services/aspose.service';
import { EntityExistsConstraint } from '../globals/validators/db.validators';

@Global()
@Module({
  imports: [GlobalHttpRequestModule],
  providers: [
    LoggerService,
    RequestService,
    EmailService,
    AsposeService,
    EntityExistsConstraint,
  ],
  exports: [
    RequestService,
    LoggerService,
    GlobalHttpRequestModule,
    EmailService,
    AsposeService,
    EntityExistsConstraint,
  ],
})
export class GlobalServicesModule {}
