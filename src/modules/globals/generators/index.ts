import { v4 as uuidv4 } from 'uuid';
import slugify from 'slugify';

export const generateSlug = (text: string, replacement = '_'): string => {
  return slugify(text, { lower: true, strict: true, trim: true, replacement });
};

export const generateUUID = (): string => {
  return uuidv4();
};

export const generateTimestamp = (): string => {
  return new Date().toISOString();
};

export const generateOTP = (length = 6): string => {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * 10)];
  }
  return otp;
};
