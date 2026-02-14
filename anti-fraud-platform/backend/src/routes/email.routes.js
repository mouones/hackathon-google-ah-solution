const express = require('express');
const router = express.Router();
const emailController = require('../controllers/email.controller');
const { authMiddleware } = require('../middleware/auth');

// All email routes require authentication
router.use(authMiddleware);

// Email analysis
router.post('/analyze', emailController.analyzeEmail.bind(emailController));

// Get history
router.get('/history', emailController.getHistory.bind(emailController));

// Get specific email details
router.get('/:id', emailController.getEmailDetails.bind(emailController));

module.exports = router;
