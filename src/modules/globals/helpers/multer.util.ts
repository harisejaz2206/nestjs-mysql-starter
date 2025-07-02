// src/utils/multer.util.ts
export function createMulterFileFromBuffer(
  buffer: Buffer,
  originalname: string,
  mimetype: string,
) {
  return {
    buffer,
    originalname,
    mimetype,
    size: buffer.length,
    fieldname: 'file',
    stream: null,
    encoding: '7bit',
    destination: '',
    filename: '',
    path: '',
  } as Express.Multer.File;
}
