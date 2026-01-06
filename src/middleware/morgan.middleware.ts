import morgan from 'morgan';
import logger from '../utils/logger';

// Extend logger to have a stream property
(logger as any).stream = {
  write: (message: string) =>
    logger.info(
      `\n**********************REQUEST_STARTED*********************\n${message.substring(0, message.lastIndexOf('\n'))}`
    ),
};

export default morgan(
  ':method :url :status :response-time ms - :res[content-length]',
  { stream: (logger as any).stream }
);

