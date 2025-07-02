import { PartialType } from '@nestjs/mapped-types';
import { SigninUserDto } from './signin-user.dto';

export class UpdateAuthDto extends PartialType(SigninUserDto) {}
