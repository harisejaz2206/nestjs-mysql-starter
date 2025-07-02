import { Module } from '@nestjs/common';
import { S3Module } from '../aws/s3/s3.module';
import { UploadsService } from './uploads.service';
import { UploadsController } from './uploads.controller';

@Module({
  imports: [S3Module],
  providers: [UploadsService],
  controllers: [UploadsController],
})
export class UploadsModule {}
