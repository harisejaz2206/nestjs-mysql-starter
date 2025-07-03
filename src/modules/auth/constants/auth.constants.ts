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