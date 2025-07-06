import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateSuperAdminUserDto } from './dto/create-super-admin-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from './entities/user.entity';
import { Repository } from 'typeorm';
import { RequestContext } from 'nestjs-request-context';
import { UserRoleEnum } from './enums/user-enums.enum';
import { UsersStatusEnum } from './enums/users.status.enum';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersListDto } from './dto/users-list.dto';
import { ListDataDto } from '../globals/dtos/response.data.dtos';
import { QueryBuilderHelper } from '../globals/helpers/query-builder.helper';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepo: Repository<UserEntity>,
  ) {}

  /**
   * Get the current authenticated user from request context
   */
  getRequestUser(): UserEntity {
    const req: any = RequestContext.currentContext.req;
    if (req.user) {
      return req.user as UserEntity;
    }
    throw new BadRequestException('User not found in the request!');
  }

  /**
   * Get current user profile with optional relations
   */
  async getCurrentUser(relations?: string[]): Promise<UserEntity> {
    const reqUser = this.getRequestUser();
    const user = await this.userRepo.findOne({
      where: { id: reqUser.id },
      relations,
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  /**
   * Create a new user
   */
  async create(userData: Partial<UserEntity>): Promise<UserEntity> {
    // Check if user already exists
    const existingUser = await this.userRepo.findOne({
      where: { email: userData.email?.toLowerCase() },
    });

    if (existingUser) {
      throw new BadRequestException('User with this email already exists');
    }

    // Hash password if provided
    if (userData.password) {
      userData.password = await bcrypt.hash(userData.password, 10);
    }

    const user = this.userRepo.create({
      ...userData,
      email: userData.email?.toLowerCase(),
      status: userData.status || UsersStatusEnum.ACTIVE,
      role: userData.role || UserRoleEnum.User,
      isEmailVerified: userData.isEmailVerified || false,
    });

    return this.userRepo.save(user);
  }

  /**
   * Get all users with pagination and filtering
   */
  async findAll(query: UsersListDto): Promise<ListDataDto<UserEntity>> {
    const { search, role, status, page = 0, perPage = 10 } = query;

    return QueryBuilderHelper
      .create(this.userRepo, 'user')
      .search(['firstName', 'lastName', 'email'], search)
      .filter('role', role)
      .filter('status', status)
      .sort('createdAt', 'DESC')
      .paginate(page, perPage)
      .execute(query);
  }

  /**
   * Get users with advanced filtering and analytics
   * Demonstrates additional QueryBuilderHelper features
   */
  async findUsersAdvanced(query: {
    search?: string;
    roles?: string[];
    statuses?: string[];
    isEmailVerified?: boolean;
    createdAfter?: Date;
    createdBefore?: Date;
    page?: number;
    perPage?: number;
  }): Promise<ListDataDto<UserEntity>> {
    const { 
      search, 
      roles, 
      statuses, 
      isEmailVerified, 
      createdAfter, 
      createdBefore,
      page = 0, 
      perPage = 10 
    } = query;

    return QueryBuilderHelper
      .create(this.userRepo, 'user')
      .search(['firstName', 'lastName', 'email', 'phoneNumber'], search)
      .filter('role', roles, 'IN')
      .filter('status', statuses, 'IN')
      .filter('isEmailVerified', isEmailVerified)
      .dateRange('createdAt', createdAfter, createdBefore)
      .sort('createdAt', 'DESC')
      .sort('firstName', 'ASC') // Secondary sort
      .paginate(page, perPage)
      .cache(`users_advanced_${JSON.stringify(query)}`, 30000) // 30 second cache
      .execute();
  }

  /**
   * Find user by ID
   */
  async findOne(id: number, relations: string[] = []): Promise<UserEntity> {
    if (!id) {
      throw new BadRequestException('ID is required');
    }

    const user = await this.userRepo.findOne({
      where: { id },
      relations,
    });

    if (!user) {
      throw new NotFoundException(`User not found with ID ${id}`);
    }

    return user;
  }

  /**
   * Find user by email
   */
  async findByEmail(email: string): Promise<UserEntity | null> {
    return this.userRepo.findOne({
      where: { email: email.toLowerCase() },
    });
  }

  /**
   * Update user
   */
  async update(id: number, updateData: UpdateUserDto): Promise<UserEntity> {
    const user = await this.findOne(id);

    // Hash password if being updated
    if (updateData.password) {
      updateData.password = await bcrypt.hash(updateData.password, 10);
    }

    // Update email to lowercase if provided
    if (updateData.email) {
      updateData.email = updateData.email.toLowerCase();
      
      // Check if email is already taken by another user
      const existingUser = await this.userRepo.findOne({
        where: { email: updateData.email },
      });
      
      if (existingUser && existingUser.id !== id) {
        throw new BadRequestException('Email already taken by another user');
      }
    }

    Object.assign(user, updateData);
    return this.userRepo.save(user);
  }

  /**
   * Soft delete user
   */
  async remove(id: number): Promise<void> {
    const user = await this.findOne(id);
    await this.userRepo.softRemove(user);
  }

  /**
   * Create a super admin user (for initial setup)
   */
  async createSuperAdmin(createUserDto: CreateSuperAdminUserDto): Promise<UserEntity> {
    return this.create({
      ...createUserDto,
      role: UserRoleEnum.Admin,
      status: UsersStatusEnum.ACTIVE,
      isEmailVerified: true,
      emailVerifiedAt: new Date(),
    });
  }
}
