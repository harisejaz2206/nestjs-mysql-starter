import {
  Body,
  Get,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateSuperAdminUserDto } from './dto/create-super-admin-user.dto';
import { GlobalResponseDto } from '../globals/dtos/global.response.dto';
import { ApiController, Auth } from '../globals/decorators/global.decorators';
import { ConfigService } from '@nestjs/config';
import { EnvKeysEnum } from '../globals/enums/env.enum';
import { ApiQuery } from '@nestjs/swagger';
import { CreateUserDto } from './dto/create-user.dto';
import { ResourcesEnum } from '../globals/enums/resouces.meta';
import { SignupUpUserDto } from './dto/signup-up-user.dto';
import { SkipDBUserInAuthGuard } from '../auth/guards/authentication.guard';
import { UpdateUserForMgmt, UpdateUserStatusDto } from './dto/update-user.dto';
import { UsersListDto } from './dto/users-list.dto';

@ApiController({
  prefix: '/users',
  tagName: 'Users',
  isBearerAuth: true,
})
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
  ) {}

  @Get('profile')
  async findOne() {
    const user = await this.usersService.getCurrentUser([
      'student',
      'role',
      'role.permissions',
    ]);
    return new GlobalResponseDto(HttpStatus.OK, 'Get User', user);
  }

  @Auth({
    isPublic: true,
  })
  @ApiQuery({
    name: 'secretCode',
    required: true,
    type: String,
  })
  @Post('super-admin')
  async createSuperAdmin(
    @Query('secretCode') secretCode: string,
    @Body() createUserDto: CreateSuperAdminUserDto,
  ) {
    const sec = this.configService.get<string>(EnvKeysEnum.MySecretForSuper);
    if (secretCode !== sec) {
      throw new UnauthorizedException('Secret does not match');
    }
    return new GlobalResponseDto(
      HttpStatus.CREATED,
      'Create User',
      await this.usersService.createUserOld(createUserDto),
    );
  }

  @Post('')
  async create(@Body() body: CreateUserDto) {
    return new GlobalResponseDto(
      HttpStatus.CREATED,
      'Create User',
      await this.usersService.createUser(body),
    );
  }

  @Get('')
  async findAll(@Query() query: UsersListDto) {
    return new GlobalResponseDto(
      HttpStatus.CREATED,
      'Create User',
      await this.usersService.findAll(query),
    );
  }

  @Put('/pending/:id/invite')
  async resendInviteEmail(@Param('id', new ParseIntPipe()) id: number) {
    return new GlobalResponseDto(
      HttpStatus.OK,
      'Resend Invite Email',
      await this.usersService.resendInviteEmail(id),
    );
  }

  @Put(':id/status')
  async updateUserStatus(
    @Param('id', new ParseIntPipe()) id: number,
    @Body() body: UpdateUserStatusDto,
  ) {
    return new GlobalResponseDto(
      HttpStatus.OK,
      'Update User Status',
      await this.usersService.updateUserStatus(id, body.status),
    );
  }

  @SkipDBUserInAuthGuard()
  @Auth({
    authorization: false,
  })
  @Post('/pending/:pending_token/signup')
  async signupUserWithToken(
    @Param('pending_token') token: string,
    @Body() body: SignupUpUserDto,
  ) {
    const firebaseUser =
      await this.usersService.getFirebaseUserInCurrentRequest();
    return new GlobalResponseDto(
      HttpStatus.CREATED,
      'User Signup Up',
      await this.usersService.signupPendingUser(token, firebaseUser, body),
    );
  }

  @Put(':id')
  async updateUserForMgmt(
    @Param('id', new ParseIntPipe()) id: number,
    @Body() body: UpdateUserForMgmt,
  ) {
    return new GlobalResponseDto(
      HttpStatus.OK,
      'Update User For Mgmt',
      await this.usersService.updateUserForMgmt(id, body),
    );
  }
}
