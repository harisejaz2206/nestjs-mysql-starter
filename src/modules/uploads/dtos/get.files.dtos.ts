import { ApiProperty } from '@nestjs/swagger';
import { IsDefinedString } from '../../globals/validators/custom.class.validators';

export class GetPresignedUrlDto {
  @ApiProperty({
    required: true,
    type: String,
    description: 'The name/path of the file to be uploaded',
  })
  @IsDefinedString()
  file_path: string;

  // @ApiProperty({
  //   required: true,
  //   type: String,
  //   description: 'The resource type for which the presigned URL is generated (i.e. Question, Answer, etc.)',
  // })
  //   @IsDefinedString()
  //   resource_type: string;
}
