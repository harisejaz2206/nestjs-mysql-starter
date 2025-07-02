import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { S3Service } from '../aws/s3/s3.service';

@Injectable()
export class UploadsService {
  constructor(private readonly s3Service: S3Service) {}

  async getPresignedUrl(filePath: string): Promise<{
    url: string;
    filePath: string;
  }> {
    try {
      const url = await this.s3Service.getSignedUrl(filePath);
      return {
        url: url,
        filePath: filePath,
      };
    } catch (error) {
      throw new HttpException(
        error?.message || 'Failed to generated URL',
        error?.status || error?.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
