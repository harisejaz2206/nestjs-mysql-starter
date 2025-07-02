import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { v4 as uuid } from 'uuid';
import { extname } from 'path';
import { EnvKeysEnum } from '../../globals/enums/env.enum';
import { addS3LoggingMiddleware } from '../middlewares/s3-logger.middleware';
import { CustomLogger } from '../../globals/CustomLogger';

@Injectable()
export class S3Service {
  private s3Client: S3Client;
  private bucket: string;

  constructor(private readonly configService: ConfigService) {
    this.s3Client = new S3Client({
      region: configService.get(EnvKeysEnum.AwsRegion),
      credentials: {
        accessKeyId: configService.get(EnvKeysEnum.AwsAccessKeyId),
        secretAccessKey: configService.get(EnvKeysEnum.AwsAccessKeySecret),
      },
    });
    addS3LoggingMiddleware(this.s3Client, new CustomLogger('S3Client'));

    this.bucket = configService.get(EnvKeysEnum.AwsS3BucketName);
  }

  async uploadFile(
    file: Express.Multer.File,
    fileKey?: string,
  ): Promise<string> {
    const key = fileKey || `${uuid()}${extname(file.originalname)}`;
    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype,
    });

    await this.s3Client.send(command);
    return key;
  }

  async checkFileExists(key: string): Promise<boolean> {
    try {
      await this.s3Client.send(
        new HeadObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      return true; // File exists
    } catch (error) {
      if (error.name === 'NoSuchKey') {
        return false; // File does not exist
      }
      return false;
    }
  }

  async getSignedUrl(
    key: string,
    checkIfExists = true,
    expiresInSeconds?: number,
  ): Promise<string> {
    if (checkIfExists) {
      const exists = await this.checkFileExists(key);
      if (!exists) throw new NotFoundException('Requested file does not exist');
    }
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });

    return getSignedUrl(this.s3Client, command, {
      expiresIn: expiresInSeconds || 60 * 60 * 24,
    }); // 24 hours
  }

  async deleteFile(key: string): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });

    await this.s3Client.send(command);
  }

  async generateUploadPresignedUrl(
    fileName: string,
    contentType: string,
  ): Promise<{ url: string; key: string }> {
    const key = `${uuid()}${extname(fileName)}`;

    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      ContentType: contentType,
    });

    const url = await getSignedUrl(this.s3Client, command, {
      expiresIn: 300, // 5 minutes
    });

    return { url, key };
  }
}
