import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { logger } from '../utils/logger';

interface AuthenticatedRequest extends Request {
  userId?: string;
  sessionId?: string;
  discordUserId?: string;
}

/**
 * Validate JWT token (for API authentication)
 */
export function validateApiKey(req: Request, res: Response, next: NextFunction) {
   const authHeader = req.headers['authorization'];

   if (!authHeader || !authHeader.startsWith('Bearer ')) {
     return res.status(401).json({
       error: 'Authorization required',
       message: 'Please provide a JWT token in the Authorization header using Bearer scheme',
     });
   }

   const token = authHeader.replace('Bearer ', '');

   try {
     // Verify the JWT token using the secret from environment
     const decoded = jwt.verify(token, config.security.jwtSecret);

     // Add decoded token information to request for use in subsequent middleware
     (req as AuthenticatedRequest).userId = (decoded as any).userId || (decoded as any).sub;
     (req as AuthenticatedRequest).sessionId = (decoded as any).sessionId;

     next();
   } catch (error) {
     logger.warn('Invalid JWT token provided', {
       ip: req.ip,
       error: error instanceof Error ? error.message : 'Unknown error'
     });

     if (error instanceof jwt.TokenExpiredError) {
       return res.status(401).json({
         error: 'Token expired',
         message: 'The JWT token has expired',
       });
     }

     if (error instanceof jwt.JsonWebTokenError) {
       return res.status(401).json({
         error: 'Invalid token',
         message: 'The JWT token is invalid',
       });
     }

     return res.status(401).json({
       error: 'Authentication failed',
       message: 'Failed to authenticate the request',
     });
   }
 }