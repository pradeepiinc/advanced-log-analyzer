/**
 * Centralized logging utility with structured logging support
 */

import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  verbose: 4,
  debug: 5,
  silly: 6
};

// Log colors
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  verbose: 'white',
  debug: 'cyan',
  silly: 'grey'
};

winston.addColors(colors);

// Custom format for structured logging
const structuredFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: [${info.service || 'App'}] ${info.message}`
  )
);

// Create base logger configuration
const createLogger = (service = 'App') => {
  const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    levels,
    defaultMeta: { service },
    transports: [
      // Console transport for development
      new winston.transports.Console({
        format: process.env.NODE_ENV === 'production' ? structuredFormat : consoleFormat
      }),
      
      // File transport for errors
      new winston.transports.File({
        filename: path.join(__dirname, '../../../logs/error.log'),
        level: 'error',
        format: structuredFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5
      }),
      
      // File transport for all logs
      new winston.transports.File({
        filename: path.join(__dirname, '../../../logs/combined.log'),
        format: structuredFormat,
        maxsize: 5242880, // 5MB
        maxFiles: 5
      })
    ],
    
    // Handle exceptions and rejections
    exceptionHandlers: [
      new winston.transports.File({
        filename: path.join(__dirname, '../../../logs/exceptions.log'),
        format: structuredFormat
      })
    ],
    
    rejectionHandlers: [
      new winston.transports.File({
        filename: path.join(__dirname, '../../../logs/rejections.log'),
        format: structuredFormat
      })
    ]
  });

  // Ensure logs directory exists
  import('fs').then(fs => {
    const logsDir = path.join(__dirname, '../../../logs');
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
  });

  return logger;
};

export { createLogger };
