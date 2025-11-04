import { Router } from 'express';
import { logger } from '../utils/logger';
import { prisma } from '../utils/database';

const router = Router();

// Security report schema validation
interface SecurityReport {
  type: string;
  url: string;
  user_agent?: string;
  body?: any;
}

// Simple rate limiting for security reports
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

function simpleRateLimit(req: any, res: any, next: any) {
  const now = Date.now();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const key = `security_${ip}`;
  
  const limit = rateLimitMap.get(key);
  if (!limit || now > limit.resetTime) {
    rateLimitMap.set(key, { count: 1, resetTime: now + 60000 }); // 1 minute window
    next();
    return;
  }
  
  if (limit.count >= 100) { // 100 requests per minute
    res.status(429).json({ error: 'Rate limit exceeded' });
    return;
  }
  
  limit.count++;
  next();
}

// XSS report endpoint
router.post('/xss-report', simpleRateLimit, async (req, res) => {
  try {
    const report: SecurityReport = req.body;
    
    // Log the XSS attempt
    logger.warn('XSS Protection Violation Report', {
      type: 'xss_report',
      url: report.url,
      user_agent: report.user_agent,
      report: report.body,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    // Store in security audit log if possible
    try {
      await prisma.auditLog.create({
        data: {
          action: 'xss_protection_violation',
          details: JSON.stringify({
            url: report.url,
            user_agent: report.user_agent,
            report: report.body,
            ip: req.ip
          }),
          timestamp: new Date(),
          severity: 'warning',
          success: true
        }
      });
    } catch (dbError) {
      logger.error('Failed to log XSS report to database:', dbError);
    }

    res.status(204).send();
  } catch (error) {
    logger.error('Error processing XSS report:', error);
    res.status(500).json({ error: 'Failed to process report' });
  }
});

// CSP report endpoint
router.post('/csp-report', simpleRateLimit, async (req, res) => {
  try {
    const report = req.body;
    
    // Log the CSP violation
    logger.warn('CSP Violation Report', {
      type: 'csp_violation',
      document_uri: report['csp-report']?.['document-uri'],
      violated_directive: report['csp-report']?.['violated-directive'],
      blocked_uri: report['csp-report']?.['blocked-uri'],
      effective_directive: report['csp-report']?.['effective-directive'],
      user_agent: report.user_agent,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    // Store in security audit log
    try {
      await prisma.auditLog.create({
        data: {
          action: 'csp_violation',
          details: JSON.stringify({
            ...report,
            ip: req.ip,
            user_agent: report.user_agent
          }),
          timestamp: new Date(),
          severity: 'error',
          success: true
        }
      });
    } catch (dbError) {
      logger.error('Failed to log CSP report to database:', dbError);
    }

    res.status(204).send();
  } catch (error) {
    logger.error('Error processing CSP report:', error);
    res.status(500).json({ error: 'Failed to process report' });
  }
});

// HSTS report endpoint
router.post('/hsts-report', simpleRateLimit, async (req, res) => {
  try {
    const report = req.body;
    
    // Log the HSTS violation
    logger.warn('HSTS Violation Report', {
      type: 'hsts_violation',
      report_uri: report['report-uri'],
      policy: report.policy,
      violation_directive: report['violation-directive'],
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    // Store in security audit log
    try {
      await prisma.auditLog.create({
        data: {
          action: 'hsts_violation',
          details: JSON.stringify({
            ...report,
            ip: req.ip
          }),
          timestamp: new Date(),
          severity: 'error',
          success: true
        }
      });
    } catch (dbError) {
      logger.error('Failed to log HSTS report to database:', dbError);
    }

    res.status(204).send();
  } catch (error) {
    logger.error('Error processing HSTS report:', error);
    res.status(500).json({ error: 'Failed to process report' });
  }
});

// CT report endpoint
router.post('/ct-report', simpleRateLimit, async (req, res) => {
  try {
    const report = req.body;
    
    // Log the certificate transparency violation
    logger.warn('Certificate Transparency Violation Report', {
      type: 'ct_violation',
      date: report.date,
      hostname: report['hostname'],
      port: report.port,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    // Store in security audit log
    try {
      await prisma.auditLog.create({
        data: {
          action: 'ct_violation',
          details: JSON.stringify({
            ...report,
            ip: req.ip
          }),
          timestamp: new Date(),
          severity: 'critical',
          success: true
        }
      });
    } catch (dbError) {
      logger.error('Failed to log CT report to database:', dbError);
    }

    res.status(204).send();
  } catch (error) {
    logger.error('Error processing CT report:', error);
    res.status(500).json({ error: 'Failed to process report' });
  }
});

// NEL report endpoint
router.post('/nel-report', simpleRateLimit, async (req, res) => {
  try {
    const report = req.body;
    
    // Log network errors
    logger.warn('Network Error Report', {
      type: 'network_error',
      uri: report.uri,
      status_code: report.status_code,
      method: report.method,
      phase: report.phase,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    res.status(204).send();
  } catch (error) {
    logger.error('Error processing NEL report:', error);
    res.status(500).json({ error: 'Failed to process report' });
  }
});

// General security reports endpoint
router.post('/reports', simpleRateLimit, async (req, res) => {
  try {
    const report = req.body;
    
    // Log the security event
    logger.warn('General Security Report', {
      type: 'security_report',
      report: report,
      ip: req.ip,
      user_agent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });

    res.status(204).send();
  } catch (error) {
    logger.error('Error processing security report:', error);
    res.status(500).json({ error: 'Failed to process report' });
  }
});

// Security headers endpoint
router.get('/headers', simpleRateLimit, async (req, res) => {
  try {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      security_headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': 'comprehensive',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Resource-Policy': 'same-origin'
      }
    });
  } catch (error) {
    logger.error('Error getting security headers info:', error);
    res.status(500).json({ error: 'Failed to get headers info' });
  }
});

export default router;