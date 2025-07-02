import { Module } from '@nestjs/common';
import { AwsService } from './aws.service';
import { AwsController } from './aws.controller';
import { S3Module } from './s3/s3.module';

@Module({
  controllers: [AwsController],
  providers: [AwsService],
  imports: [S3Module],
  exports: [S3Module],
})
export class AwsModule {}
