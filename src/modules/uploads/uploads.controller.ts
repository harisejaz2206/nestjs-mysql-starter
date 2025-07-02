import { ApiController } from '../globals/decorators/global.decorators';
import { UploadsService } from './uploads.service';
import { Get, HttpStatus, Query } from '@nestjs/common';
import { GlobalResponseDto } from '../globals/dtos/global.response.dto';
import { GetPresignedUrlDto } from './dtos/get.files.dtos';
import { ApiOkResponse } from '@nestjs/swagger';

@ApiController({
  prefix: 'uploads',
  tagName: 'Uploads',
  isBearerAuth: true,
})
export class UploadsController {
  constructor(private readonly uploadsService: UploadsService) {}

  @ApiOkResponse({
    description: 'Get presigned URL for file upload',
    type: GlobalResponseDto<{
      url: string;
      filePath: string;
    }>,
    example: {
      statusCode: 200,
      message: 'Presigned URL for file upload',
      data: {
        url: 'https://example-bucket.s3.amazonaws.com/uploads/file.txt?AWSAccessKeyId=AKIA...',
        filePath: 'uploads/file.txt',
      },
    },
  })
  @Get('presigned-url')
  async getPresignedUrl(@Query() query: GetPresignedUrlDto) {
    return new GlobalResponseDto(
      HttpStatus.OK,
      'Presigned URL for file upload',
      await this.uploadsService.getPresignedUrl(query.file_path),
    );
  }
}
