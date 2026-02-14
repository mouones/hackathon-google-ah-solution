/**
 * Authentication Controller
 * Handles user registration, login, and JWT token management
 */

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/database');

class AuthController {
  /**
   * Register new user
   */
  async register(req, res) {
    try {
      const { email, password, name, organization, role = 'citizen' } = req.body;

      // Validate input
      if (!email || !password || !name) {
        return res.status(400).json({ error: 'Email, password, and name are required' });
      }

      // Check if user exists
      const [existing] = await pool.query(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );

      if (existing.length > 0) {
        return res.status(409).json({ error: 'User already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user
      const [result] = await pool.query(
        'INSERT INTO users (email, password_hash, full_name, organization, role, created_at) VALUES (?, ?, ?, ?, ?, NOW())',
        [email, hashedPassword, name, organization, role]
      );

      // Generate token
      const token = jwt.sign(
        { userId: result.insertId, email, role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE || '7d' }
      );

      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: result.insertId,
          email,
          name,
          role
        },
        token
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  }

  /**
   * Login user
   */
  async login(req, res) {
    try {
      const { email, password } = req.body;

      // Validate input
      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }

      // Find user
      const [users] = await pool.query(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );

      if (users.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = users[0];

      // Check if account is locked
      if (user.account_locked) {
        return res.status(403).json({ error: 'Account is locked. Contact administrator.' });
      }

      // Verify password
      const isValid = await bcrypt.compare(password, user.password_hash);

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate token
      const token = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRE || '7d' }
      );

      // Update last login
      await pool.query(
        'UPDATE users SET last_login = NOW() WHERE id = ?',
        [user.id]
      );

      res.json({
        message: 'Login successful',
        user: {
          id: user.id,
          email: user.email,
          name: user.full_name,
          role: user.role,
          organization: user.organization
        },
        token,
        forcePasswordReset: user.force_password_reset
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  }

  /**
   * Get current user profile
   */
  async getProfile(req, res) {
    try {
      const [users] = await pool.query(
        'SELECT id, email, full_name as name, organization, role, created_at, last_login FROM users WHERE id = ?',
        [req.user.userId]
      );

      if (users.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({ user: users[0] });

    } catch (error) {
      console.error('Profile error:', error);
      res.status(500).json({ error: 'Failed to get profile' });
    }
  }
}

module.exports = new AuthController();
