export const AUTH_CONSTANTS = {
  // OTP Configuration
  OTP_LENGTH: 4,
  OTP_MIN: 1000,
  OTP_MAX: 9999,
  DEFAULT_OTP_EXPIRY_MINUTES: 15,

  // Token Configuration
  TOKEN_EXPIRES_SECONDS: 86400, // 24 hours
  DEFAULT_JWT_EXPIRY: '24h',
  DEFAULT_REFRESH_EXPIRY: '7d',

  // Security
  DEFAULT_BCRYPT_ROUNDS: 10,
  MIN_JWT_SECRET_LENGTH: 32,
  LAST_API_CALL_UPDATE_THRESHOLD: 300000, // 5 minutes in milliseconds

  // Rate Limiting
  RATE_LIMIT: {
    LOGIN: { limit: 5, ttl: 60000 },          // 5 attempts per minute
    REGISTER: { limit: 3, ttl: 60000 },       // 3 registrations per minute
    VERIFY_EMAIL: { limit: 10, ttl: 60000 },  // 10 verification attempts per minute
    FORGOT_PASSWORD: { limit: 3, ttl: 60000 }, // 3 forgot password requests per minute
    RESET_PASSWORD: { limit: 5, ttl: 60000 },  // 5 reset attempts per minute
    RESEND_OTP: { limit: 3, ttl: 60000 },     // 3 resend attempts per minute
  },

  // Error Messages
  ERRORS: {
    INVALID_CREDENTIALS: 'Invalid credentials',
    EMAIL_NOT_VERIFIED: 'Email not verified',
    ACCOUNT_INACTIVE: 'Account is inactive',
    USER_NOT_FOUND: 'User not found',
    USER_ALREADY_EXISTS: 'User already exists',
    INVALID_OTP: 'Invalid OTP or email',
    OTP_EXPIRED: 'OTP has expired',
    OTP_STILL_VALID: 'Current OTP is still valid. Please wait before requesting a new one.',
    JWT_SECRET_MISSING: 'JWT secrets not configured',
    TOKEN_ERROR: 'Token error',
    RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later.',
  },

  // Success Messages
  SUCCESS: {
    LOGIN: 'Login successful',
    REGISTRATION: 'Registration successful. Please check your email to verify your account.',
    EMAIL_VERIFIED: 'Email verified successfully',
    PASSWORD_RESET_SENT: 'Password reset OTP sent to your email',
    PASSWORD_RESET: 'Password reset successful',
    OTP_SENT: 'OTP sent successfully',
    TOKEN_REFRESHED: 'Token refreshed successfully',
  },
}; 