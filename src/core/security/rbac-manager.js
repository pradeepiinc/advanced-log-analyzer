/**
 * Role-Based Access Control (RBAC) Manager
 * Handles user authentication, authorization, and compliance features
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { getConfigManager } from '../config/config-manager.js';

class RBACManager extends EventEmitter {
  constructor() {
    super();
    this.logger = createLogger('RBACManager');
    this.config = getConfigManager();
    
    // In-memory stores (in production, use persistent storage)
    this.users = new Map();
    this.roles = new Map();
    this.permissions = new Map();
    this.sessions = new Map();
    this.auditLog = [];
    
    this.initializeDefaultRoles();
    this.initializeDefaultUsers();
  }

  initializeDefaultRoles() {
    // Define default roles and permissions
    const defaultRoles = {
      'super-admin': {
        name: 'Super Administrator',
        permissions: ['*'], // All permissions
        description: 'Full system access'
      },
      'admin': {
        name: 'Administrator',
        permissions: [
          'logs:read', 'logs:write', 'logs:delete',
          'alerts:read', 'alerts:write', 'alerts:delete',
          'users:read', 'users:write',
          'config:read', 'config:write',
          'dashboards:read', 'dashboards:write',
          'integrations:read', 'integrations:write'
        ],
        description: 'Administrative access to most features'
      },
      'analyst': {
        name: 'Security Analyst',
        permissions: [
          'logs:read', 'logs:search',
          'alerts:read', 'alerts:acknowledge',
          'dashboards:read',
          'topology:read',
          'anomalies:read'
        ],
        description: 'Read access for analysis and investigation'
      },
      'operator': {
        name: 'System Operator',
        permissions: [
          'logs:read',
          'alerts:read', 'alerts:acknowledge',
          'dashboards:read',
          'health:read'
        ],
        description: 'Basic operational access'
      },
      'viewer': {
        name: 'Read-Only Viewer',
        permissions: [
          'logs:read',
          'alerts:read',
          'dashboards:read'
        ],
        description: 'Read-only access to logs and dashboards'
      }
    };

    for (const [roleId, roleData] of Object.entries(defaultRoles)) {
      this.roles.set(roleId, {
        id: roleId,
        ...roleData,
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    this.logger.info(`Initialized ${this.roles.size} default roles`);
  }

  async initializeDefaultUsers() {
    // Create default admin user
    const adminUser = this.config.get('server.adminUser', 'admin');
    const adminPass = this.config.get('server.adminPass', 'admin123');
    
    try {
      await this.createUser({
        username: adminUser,
        password: adminPass,
        email: 'admin@localhost',
        roles: ['super-admin'],
        isActive: true
      });
      
      this.logger.info('Default admin user created');
    } catch (error) {
      this.logger.warn('Failed to create default admin user:', error.message);
    }
  }

  async createUser(userData) {
    const { username, password, email, roles = ['viewer'], isActive = true } = userData;
    
    if (this.users.has(username)) {
      throw new Error(`User ${username} already exists`);
    }

    // Validate roles
    for (const role of roles) {
      if (!this.roles.has(role)) {
        throw new Error(`Role ${role} does not exist`);
      }
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    
    const user = {
      id: crypto.randomUUID(),
      username,
      email,
      passwordHash,
      roles,
      isActive,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastLogin: null,
      loginAttempts: 0,
      lockedUntil: null
    };

    this.users.set(username, user);
    
    this.auditLog.push({
      timestamp: new Date(),
      action: 'user.created',
      actor: 'system',
      target: username,
      details: { roles }
    });

    this.emit('user-created', { username, roles });
    this.logger.info(`User created: ${username}`);
    
    return { id: user.id, username, email, roles, isActive };
  }

  async authenticateUser(username, password) {
    const user = this.users.get(username);
    
    if (!user) {
      this.auditLog.push({
        timestamp: new Date(),
        action: 'auth.failed',
        actor: username,
        reason: 'user_not_found'
      });
      throw new Error('Invalid credentials');
    }

    if (!user.isActive) {
      this.auditLog.push({
        timestamp: new Date(),
        action: 'auth.failed',
        actor: username,
        reason: 'account_disabled'
      });
      throw new Error('Account is disabled');
    }

    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      this.auditLog.push({
        timestamp: new Date(),
        action: 'auth.failed',
        actor: username,
        reason: 'account_locked'
      });
      throw new Error('Account is temporarily locked');
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    
    if (!isValidPassword) {
      user.loginAttempts += 1;
      
      // Lock account after 5 failed attempts
      if (user.loginAttempts >= 5) {
        user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        this.logger.warn(`Account locked due to failed login attempts: ${username}`);
      }
      
      this.auditLog.push({
        timestamp: new Date(),
        action: 'auth.failed',
        actor: username,
        reason: 'invalid_password',
        attempts: user.loginAttempts
      });
      
      throw new Error('Invalid credentials');
    }

    // Reset login attempts on successful auth
    user.loginAttempts = 0;
    user.lockedUntil = null;
    user.lastLogin = new Date();

    this.auditLog.push({
      timestamp: new Date(),
      action: 'auth.success',
      actor: username
    });

    this.emit('user-authenticated', { username });
    return user;
  }

  generateToken(user) {
    const payload = {
      userId: user.id,
      username: user.username,
      roles: user.roles,
      permissions: this.getUserPermissions(user.username)
    };

    const secret = this.config.get('server.sessionSecret') || 'fallback-secret';
    const token = jwt.sign(payload, secret, { 
      expiresIn: '8h',
      issuer: 'production-log-analyzer'
    });

    // Store session
    const sessionId = crypto.randomUUID();
    this.sessions.set(sessionId, {
      userId: user.id,
      username: user.username,
      token,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000) // 8 hours
    });

    return { token, sessionId };
  }

  verifyToken(token) {
    try {
      const secret = this.config.get('server.sessionSecret') || 'fallback-secret';
      const payload = jwt.verify(token, secret);
      
      // Check if session exists and is valid
      const session = Array.from(this.sessions.values())
        .find(s => s.token === token && s.expiresAt > new Date());
      
      if (!session) {
        throw new Error('Session not found or expired');
      }

      return payload;
    } catch (error) {
      this.logger.warn('Token verification failed:', error.message);
      throw new Error('Invalid or expired token');
    }
  }

  getUserPermissions(username) {
    const user = this.users.get(username);
    if (!user) return [];

    const permissions = new Set();
    
    for (const roleId of user.roles) {
      const role = this.roles.get(roleId);
      if (role) {
        for (const permission of role.permissions) {
          permissions.add(permission);
        }
      }
    }

    return Array.from(permissions);
  }

  hasPermission(username, requiredPermission) {
    const permissions = this.getUserPermissions(username);
    
    // Super admin has all permissions
    if (permissions.includes('*')) {
      return true;
    }

    // Check exact permission match
    if (permissions.includes(requiredPermission)) {
      return true;
    }

    // Check wildcard permissions (e.g., 'logs:*' matches 'logs:read')
    const wildcardPermissions = permissions.filter(p => p.endsWith(':*'));
    for (const wildcardPerm of wildcardPermissions) {
      const prefix = wildcardPerm.slice(0, -1); // Remove '*'
      if (requiredPermission.startsWith(prefix)) {
        return true;
      }
    }

    return false;
  }

  // Middleware for Express routes
  requireAuth() {
    return (req, res, next) => {
      try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Missing or invalid authorization header' });
        }

        const token = authHeader.substring(7);
        const payload = this.verifyToken(token);
        
        req.user = payload;
        next();
      } catch (error) {
        return res.status(401).json({ error: 'Authentication failed' });
      }
    };
  }

  requirePermission(permission) {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      if (!this.hasPermission(req.user.username, permission)) {
        this.auditLog.push({
          timestamp: new Date(),
          action: 'access.denied',
          actor: req.user.username,
          resource: permission,
          ip: req.ip
        });
        
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      next();
    };
  }

  // PII Detection and Redaction
  detectPII(text) {
    const piiPatterns = {
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      ssn: /\b\d{3}-?\d{2}-?\d{4}\b/g,
      creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
      ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
      apiKey: /\b[A-Za-z0-9]{32,}\b/g
    };

    const detected = [];
    
    for (const [type, pattern] of Object.entries(piiPatterns)) {
      const matches = text.match(pattern);
      if (matches) {
        detected.push({ type, matches: [...new Set(matches)] });
      }
    }

    return detected;
  }

  redactPII(text, mode = 'hash') {
    const piiPatterns = {
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      ssn: /\b\d{3}-?\d{2}-?\d{4}\b/g,
      creditCard: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
      apiKey: /\b[A-Za-z0-9]{32,}\b/g
    };

    let redactedText = text;
    const redactions = [];

    for (const [type, pattern] of Object.entries(piiPatterns)) {
      redactedText = redactedText.replace(pattern, (match) => {
        let replacement;
        
        switch (mode) {
          case 'hash':
            replacement = `[${type.toUpperCase()}:${crypto.createHash('sha256').update(match).digest('hex').substring(0, 8)}]`;
            break;
          case 'mask':
            replacement = match.length > 4 ? 
              match.substring(0, 2) + '*'.repeat(match.length - 4) + match.substring(match.length - 2) :
              '*'.repeat(match.length);
            break;
          case 'remove':
            replacement = `[${type.toUpperCase()}_REDACTED]`;
            break;
          default:
            replacement = match;
        }
        
        redactions.push({ type, original: match, redacted: replacement });
        return replacement;
      });
    }

    return { redactedText, redactions };
  }

  // Compliance and Audit Functions
  getAuditLog(filters = {}) {
    let filteredLog = [...this.auditLog];

    if (filters.action) {
      filteredLog = filteredLog.filter(entry => entry.action === filters.action);
    }

    if (filters.actor) {
      filteredLog = filteredLog.filter(entry => entry.actor === filters.actor);
    }

    if (filters.startDate) {
      filteredLog = filteredLog.filter(entry => entry.timestamp >= filters.startDate);
    }

    if (filters.endDate) {
      filteredLog = filteredLog.filter(entry => entry.timestamp <= filters.endDate);
    }

    return filteredLog.sort((a, b) => b.timestamp - a.timestamp);
  }

  generateComplianceReport() {
    const now = new Date();
    const last30Days = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    
    const recentAuditEntries = this.getAuditLog({ startDate: last30Days });
    
    const report = {
      generatedAt: now,
      period: { start: last30Days, end: now },
      summary: {
        totalUsers: this.users.size,
        activeUsers: Array.from(this.users.values()).filter(u => u.isActive).length,
        totalRoles: this.roles.size,
        auditEntries: recentAuditEntries.length
      },
      userActivity: {
        logins: recentAuditEntries.filter(e => e.action === 'auth.success').length,
        failedLogins: recentAuditEntries.filter(e => e.action === 'auth.failed').length,
        accessDenials: recentAuditEntries.filter(e => e.action === 'access.denied').length
      },
      securityEvents: {
        accountLockouts: recentAuditEntries.filter(e => e.reason === 'account_locked').length,
        piiDetections: recentAuditEntries.filter(e => e.action === 'pii.detected').length
      },
      recommendations: []
    };

    // Add recommendations based on findings
    if (report.userActivity.failedLogins > report.userActivity.logins * 0.1) {
      report.recommendations.push('High failed login rate detected - consider implementing additional security measures');
    }

    if (report.securityEvents.accountLockouts > 0) {
      report.recommendations.push('Account lockouts detected - review user training and password policies');
    }

    return report;
  }

  // Session management
  revokeSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session) {
      this.sessions.delete(sessionId);
      
      this.auditLog.push({
        timestamp: new Date(),
        action: 'session.revoked',
        actor: session.username,
        sessionId
      });
      
      this.emit('session-revoked', { sessionId, username: session.username });
      return true;
    }
    return false;
  }

  revokeAllUserSessions(username) {
    let revokedCount = 0;
    
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.username === username) {
        this.sessions.delete(sessionId);
        revokedCount++;
      }
    }

    if (revokedCount > 0) {
      this.auditLog.push({
        timestamp: new Date(),
        action: 'sessions.revoked.all',
        actor: 'system',
        target: username,
        count: revokedCount
      });
      
      this.emit('user-sessions-revoked', { username, count: revokedCount });
    }

    return revokedCount;
  }

  // Cleanup expired sessions
  cleanupExpiredSessions() {
    const now = new Date();
    let cleanedCount = 0;

    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.expiresAt <= now) {
        this.sessions.delete(sessionId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      this.logger.info(`Cleaned up ${cleanedCount} expired sessions`);
    }

    return cleanedCount;
  }

  // Get user info (without sensitive data)
  getUserInfo(username) {
    const user = this.users.get(username);
    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles,
      permissions: this.getUserPermissions(username),
      isActive: user.isActive,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    };
  }

  // List all users (admin only)
  listUsers() {
    return Array.from(this.users.values()).map(user => ({
      id: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles,
      isActive: user.isActive,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      loginAttempts: user.loginAttempts,
      lockedUntil: user.lockedUntil
    }));
  }

  // Update user
  async updateUser(username, updates) {
    const user = this.users.get(username);
    if (!user) {
      throw new Error('User not found');
    }

    const allowedUpdates = ['email', 'roles', 'isActive'];
    const actualUpdates = {};

    for (const [key, value] of Object.entries(updates)) {
      if (allowedUpdates.includes(key)) {
        actualUpdates[key] = value;
        user[key] = value;
      }
    }

    user.updatedAt = new Date();

    this.auditLog.push({
      timestamp: new Date(),
      action: 'user.updated',
      actor: 'system', // Should be the acting user in real implementation
      target: username,
      changes: actualUpdates
    });

    this.emit('user-updated', { username, updates: actualUpdates });
    return this.getUserInfo(username);
  }
}

// Singleton instance
let rbacManager = null;

export function getRBACManager() {
  if (!rbacManager) {
    rbacManager = new RBACManager();
  }
  return rbacManager;
}

export { RBACManager };
