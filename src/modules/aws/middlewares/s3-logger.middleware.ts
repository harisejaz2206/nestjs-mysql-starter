import { FinalizeHandlerArguments, MetadataBearer } from '@aws-sdk/types';
import { S3Client } from '@aws-sdk/client-s3';
import { CustomLogger } from '../../globals/CustomLogger';

export function addS3LoggingMiddleware(
  client: S3Client,
  logger = new CustomLogger('S3'),
) {
  client.middlewareStack.add(
    (next, context) => async (args: FinalizeHandlerArguments<any>) => {
      logger.log(`[S3] Command: ${context.commandName}`);
      const newArgs = JSON.parse(JSON.stringify(args));
      delete (newArgs.request as any)?.headers;
      delete (newArgs.request as any)?.body?.data;
      logger.debug(`[S3] Request: ${JSON.stringify(newArgs.request)}`);

      try {
        const result = await next(args);
        logger.debug(
          `[S3] Response: ${JSON.stringify(result as unknown as MetadataBearer)}`,
        );
        return result;
      } catch (error) {
        logger.error(`[S3] Error in ${context.commandName}: ${error.message}`);
        throw error;
      }
    },
    {
      step: 'finalizeRequest', // after serialization
      name: 's3LoggerMiddleware',
    },
  );
}
