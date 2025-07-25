import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserEntity } from '../../users/entities/user.entity';

@Injectable()
export class UserQueryService {
  private readonly selectUserFields = [
    'id',
    'email',
    'firstName',
    'lastName',
    'role',
    'avatar',
    'status',
    'isEmailVerified',
    'emailVerifiedAt',
    'lastApiCallAt',
    'tokenVersion',
  ];

  // Auth-specific fields (minimal but sufficient for all guards)
  private readonly authValidationFields = [
    'id', 'email', 'firstName', 'lastName', 'role',
    'status', 'isEmailVerified', 'tokenVersion', 'lastApiCallAt'
  ];

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
  ) {}

  /**
   * Find user by email with password field
   */
  async findUserWithPassword(email: string): Promise<UserEntity> {
    try {
      return await this.userRepository.findOne({
        where: { email: email.toLowerCase() },
        select: [
          ...this.selectUserFields,
          'password',
          'otpExpireAt',
        ] as (keyof UserEntity)[],
      });
    } catch (error) {
      console.error('Database error in findUserWithPassword:', error);
      throw error; // Re-throw to be handled by calling service
    }
  }

  /**
   * Find user by email
   */
  async findUserByEmail(email: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: { email: email.toLowerCase() },
      select: this.selectUserFields as (keyof UserEntity)[],
    });
  }

  /**
   * Find user by email and OTP combination (secure method)
   * 
   * @description Securely finds user using both email and OTP to prevent enumeration attacks
   * 
   * @param email - User email address (converted to lowercase)
   * @param otp - 4-digit OTP string (converted to number)
   * @returns Promise<UserEntity> - User entity with OTP expiry field
   * 
   * @security Prevents OTP enumeration by requiring both email and OTP
   * @note Returns null if no user found with this email/OTP combination
   */
  async findUserByEmailAndOtp(email: string, otp: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: {
        email: email.toLowerCase(),
        otp: Number(otp),
      },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof UserEntity)[],
    });
  }

  /**
   * Find user with OTP expiry field
   */
  async findUserWithOtpExpiry(email: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: { email: email.toLowerCase() },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof UserEntity)[],
    });
  }

  /**
   * Check if email already exists
   */
  async emailExists(email: string): Promise<boolean> {
    const user = await this.userRepository.findOne({
      where: { email: email.toLowerCase() },
      select: ['id'],
    });
    return !!user;
  }

  /**
   * Update user's last API call timestamp
   */
  async updateUserLastApiCall(userId: number): Promise<void> {
    await this.userRepository.update(userId, {
      lastApiCallAt: new Date(),
    });
  }

  /**
   * Mark user as email verified and clear OTP
   * 
   * @description Updates user verification status and cleans up OTP data
   * 
   * **Database Updates:**
   * - Sets isEmailVerified = true
   * - Sets emailVerifiedAt = current timestamp
   * - Clears otp = null
   * - Clears otpExpireAt = null
   * 
   * @param userId - User ID to update
   * @returns Promise<void> - No return value
   * 
   * @note This is a one-time operation per user registration
   */
  async markUserAsVerified(userId: number): Promise<void> {
    await this.userRepository.update(userId, {
      isEmailVerified: true,
      emailVerifiedAt: new Date(),
      otp: null,
      otpExpireAt: null,
    });
  }

  /**
   * Update user OTP
   */
  async updateUserOtp(userId: number, otp: number, otpExpireAt: number): Promise<void> {
    await this.userRepository.update(userId, {
      otp,
      otpExpireAt,
    });
  }

  /**
   * Update user password and clear OTP
   */
  async updateUserPassword(userId: number, hashedPassword: string): Promise<void> {
    await this.userRepository.update(userId, {
      password: hashedPassword,
      otp: null,
      otpExpireAt: null,
    });
  }

  /**
   * Create new user
   */
  async createUser(userData: Partial<UserEntity>): Promise<UserEntity> {
    try {
      const user = this.userRepository.create(userData);
      return await this.userRepository.save(user);
    } catch (error) {
      console.error('Database error in createUser:', error);
      throw error; // Re-throw to be handled by calling service
    }
  }

  /**
   * Increment user's token version (invalidates all existing tokens)
   */
  async incrementTokenVersion(userId: number): Promise<void> {
    try {
      await this.userRepository.increment(
        { id: userId },
        'tokenVersion',
        1
      );
    } catch (error) {
      console.error('Database error in incrementTokenVersion:', error);
      throw error;
    }
  }

  /**
   * Get user with token version for validation
   * Returns full user fields needed for auth guards and decorators
   */
  async findUserWithTokenVersion(userId: number): Promise<UserEntity | null> {
    try {
      return await this.userRepository.findOne({
        where: { id: userId },
        select: this.selectUserFields as (keyof UserEntity)[], // Use full fields instead of minimal
      });
    } catch (error) {
      console.error('Database error in findUserWithTokenVersion:', error);
      throw error;
    }
  }
} 