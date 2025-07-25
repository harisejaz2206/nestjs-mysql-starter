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
  UseGuards,
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
import { RolesGuard } from '../auth/guards/roles.guard';
import { AdminOnly } from '../auth/decorators/roles.decorator';
import { AuthGuard } from '../auth/guards/auth.guard';
import { ResourceOwnershipGuard, ResourceOwnership } from '../auth/guards/resource-ownership.guard';
import { OrderByFieldGuard } from '../globals/guards/req.query.guards';

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
   * Get current user profile - Any authenticated user can access their own profile
   */
  @Get('profile')
  @UseGuards(AuthGuard)  // Only authentication required, no role restriction
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
   * Only admins should be able to view all users
   */
  @Get()
  @UseGuards(AuthGuard, RolesGuard, OrderByFieldGuard(UserEntity))
  @AdminOnly()
  async findAll(@Query() query: UsersListDto): Promise<GlobalResponseDto<any>> {
    const result = await this.usersService.findAll(query);
    return new GlobalResponseDto(HttpStatus.OK, 'Get All Users', result);
  }

  /**
   * Get users with advanced filtering 
   * Advanced user management should be admin-only
   */
  @Get('advanced')
  @UseGuards(AuthGuard, RolesGuard)
  @AdminOnly() 
  async findUsersAdvanced(@Query() query: {
    search?: string;
    roles?: string[];
    statuses?: string[];
    isEmailVerified?: boolean;
    createdAfter?: string;
    createdBefore?: string;
    page?: number;
    perPage?: number;
  }): Promise<GlobalResponseDto<any>> {
    const processedQuery = {
      ...query,
      createdAfter: query.createdAfter ? new Date(query.createdAfter) : undefined,
      createdBefore: query.createdBefore ? new Date(query.createdBefore) : undefined,
    };
    
    const result = await this.usersService.findUsersAdvanced(processedQuery);
    return new GlobalResponseDto(HttpStatus.OK, 'Get Users Advanced', result);
  }

  /**
   * Get user by ID 
   * Users can view their own profile, admins can view any user
   */
  @Get(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ resourceType: 'user profile' })
  async findOne(@Param('id', ParseIntPipe) id: number): Promise<GlobalResponseDto<UserEntity>> {
    const user = await this.usersService.findOne(id);
    return new GlobalResponseDto(HttpStatus.OK, 'Get User', user);
  }

  /**
   * Get user by ID (Admin Only - for admin panel)
   * Admins can view any user's details with full access
   */
  @Get('admin/:id')
  @UseGuards(AuthGuard, RolesGuard)
  @AdminOnly() 
  async findOneAdmin(@Param('id', ParseIntPipe) id: number): Promise<GlobalResponseDto<UserEntity>> {
    const user = await this.usersService.findOne(id);
    return new GlobalResponseDto(HttpStatus.OK, 'Get User (Admin)', user);
  }

  /**
   * Update user profile
   * Users can update their own profile, admins can update any user
   */
  @Put(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ resourceType: 'user profile' })
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUserDto: UpdateUserDto,
  ): Promise<GlobalResponseDto<UserEntity>> {
    const user = await this.usersService.update(id, updateUserDto);
    return new GlobalResponseDto(HttpStatus.OK, 'User Updated', user);
  }

  /**
   * Update user by ID (Admin Only)
   * Admins can update any user with full privileges 
   */
  @Put('admin/:id')
  @UseGuards(AuthGuard, RolesGuard)
  @AdminOnly() 
  async updateAdmin(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateUserDto: UpdateUserDto,
  ): Promise<GlobalResponseDto<UserEntity>> {
    const user = await this.usersService.update(id, updateUserDto);
    return new GlobalResponseDto(HttpStatus.OK, 'User Updated (Admin)', user);
  }

  /**
   * Delete user by ID (soft delete) 
   * User deletion should be admin-only
   */
  @Delete(':id')
  @UseGuards(AuthGuard, RolesGuard)
  @AdminOnly() 
  async remove(@Param('id', ParseIntPipe) id: number): Promise<GlobalResponseDto<null>> {
    await this.usersService.remove(id);
    return new GlobalResponseDto(HttpStatus.OK, 'User Deleted', null);
  }
}
