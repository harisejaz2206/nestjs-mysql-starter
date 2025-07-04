import {
  Body,
  Delete,
  Get,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateSuperAdminUserDto } from './dto/create-super-admin-user.dto';
import { GlobalResponseDto } from '../globals/dtos/global.response.dto';
import { ApiController, Auth } from '../globals/decorators/global.decorators';
import { ConfigService } from '@nestjs/config';
import { EnvKeysEnum } from '../globals/enums/env.enum';
import { ApiQuery } from '@nestjs/swagger';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersListDto } from './dto/users-list.dto';
import { UserEntity } from './entities/user.entity';

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

  /**
   * Get current user profile
   */
  @Get('profile')
  async getProfile(): Promise<GlobalResponseDto<UserEntity>> {
    const user = await this.usersService.getCurrentUser();
    return new GlobalResponseDto(HttpStatus.OK, 'Get User Profile', user);
  }

  /**
   * Create super admin user (protected by secret code)
   */
  @Auth({ isPublic: true })
  @ApiQuery({
    name: 'secretCode',
    required: true,
    type: String,
  })
  @Post('super-admin')
  async createSuperAdmin(
    @Query('secretCode') secretCode: string,
    @Body() createUserDto: CreateSuperAdminUserDto,
  ): Promise<GlobalResponseDto<UserEntity>> {
    const sec = this.configService.get<string>(EnvKeysEnum.MySecretForSuper);
    if (secretCode !== sec) {
      throw new UnauthorizedException('Secret does not match');
    }
    const user = await this.usersService.createSuperAdmin(createUserDto);
    return new GlobalResponseDto(
      HttpStatus.CREATED,
      'Super Admin User Created',
      user,
    );
  }

  /**
   * Get all users with pagination and filtering
   */
  @Get()
  async findAll(@Query() query: UsersListDto): Promise<GlobalResponseDto<any>> {
    const result = await this.usersService.findAll(query);
    return new GlobalResponseDto(HttpStatus.OK, 'Get All Users', result);
  }

  /**
   * Get user by ID
   */
  @Get(':id')
  async findOne(@Param('id', ParseIntPipe) id: number): Promise<GlobalResponseDto<UserEntity>> {
    const user = await this.usersService.findOne(id);
    return new GlobalResponseDto(HttpStatus.OK, 'Get User', user);
  }

  /**
   * Update user by ID
   */
  @Put(':id')
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUserDto: UpdateUserDto,
  ): Promise<GlobalResponseDto<UserEntity>> {
    const user = await this.usersService.update(id, updateUserDto);
    return new GlobalResponseDto(HttpStatus.OK, 'User Updated', user);
  }

  /**
   * Delete user by ID (soft delete)
   */
  @Delete(':id')
  async remove(@Param('id', ParseIntPipe) id: number): Promise<GlobalResponseDto<null>> {
    await this.usersService.remove(id);
    return new GlobalResponseDto(HttpStatus.OK, 'User Deleted', null);
  }
}
