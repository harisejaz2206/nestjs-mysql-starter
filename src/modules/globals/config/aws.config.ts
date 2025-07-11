export default () => ({
  aws: {
    region: process.env.AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    s3: { bucketName: process.env.AWS_S3_BUCKET_NAME },
  },
});
