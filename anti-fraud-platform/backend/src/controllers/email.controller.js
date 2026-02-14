/**
 * Email Analysis Controller
 * Handles email analysis requests using all detection services
 */

const pool = require('../config/database');
const axios = require('axios');
const charDetectionService = require('../services/char-detection.service');
const formalityService = require('../services/formality.service');
const nameMatchService = require('../services/name-match.service');
const linkAnalyzerService = require('../services/link-analyzer.service');
const virusTotalService = require('../services/virustotal.service');
const automatedResponseService = require('../services/automated-response.service');

class EmailController {
  /**
   * Analyze email for phishing threats
   */
  async analyzeEmail(req, res) {
    try {
      const { subject, body, sender, senderName } = req.body;
      const userId = req.user.userId;

      // Validate input
      if (!subject || !body || !sender) {
        return res.status(400).json({ 
          error: 'Subject, body, and sender are required' 
        });
      }

      const analysisStart = Date.now();
      const emailData = { subject, body, sender, senderName };
      
      // Extract sender domain
      const senderDomain = sender.split('@')[1];

      // Initialize analysis results
      const analysis = {
        threatScore: 0,
        isPhishing: false,
        confidence: 0,
        checks: {}
      };

      // 1. ML Model Prediction
      try {
        const mlResponse = await axios.post(`${process.env.ML_SERVICE_URL}/predict`, {
          subject,
          body,
          sender,
          sender_name: senderName
        }, { timeout: 5000 });

        analysis.checks.ml_prediction = mlResponse.data;
        analysis.threatScore += mlResponse.data.threat_score * 0.4; // 40% weight
      } catch (error) {
        console.error('ML service error:', error.message);
        analysis.checks.ml_prediction = { error: 'ML service unavailable' };
      }

      // 2. Character Substitution Detection
      const charDetection = charDetectionService.detect(`${subject} ${body}`);
      const senderCheck = charDetectionService.analyzeSenderEmail(sender, [
        'paypal', 'amazon', 'microsoft', 'google', 'bank'
      ]);
      
      analysis.checks.char_substitution = {
        ...charDetection,
        sender_check: senderCheck
      };
      
      if (charDetection.hasSubstitution) {
        analysis.threatScore += charDetection.score * 0.15; // 15% weight
      }
      if (senderCheck.isSpoofed) {
        analysis.threatScore += senderCheck.score * 0.2; // 20% weight
      }

      // 3. Email Formality Analysis
      const formalityCheck = formalityService.analyze(emailData);
      analysis.checks.formality = formalityCheck;
      
      // Low formality increases threat score
      if (formalityCheck.formalityScore < 50) {
        analysis.threatScore += (50 - formalityCheck.formalityScore) * 0.1;
      }

      // 4. Name Mismatch Detection
      const nameCheck = nameMatchService.analyze(emailData);
      analysis.checks.name_mismatch = nameCheck;
      
      if (nameCheck.hasMismatch) {
        const mismatchScore = {
          critical: 25,
          high: 15,
          medium: 8
        }[nameCheck.severity] || 0;
        analysis.threatScore += mismatchScore;
      }

      // 5. Link Analysis
      const urls = linkAnalyzerService.extractURLs(`${subject} ${body}`);
      if (urls.length > 0) {
        const linkAnalysis = await linkAnalyzerService.analyzeAllURLs(`${subject} ${body}`);
        analysis.checks.links = linkAnalysis;
        
        if (linkAnalysis.hasSuspiciousLinks) {
          analysis.threatScore += linkAnalysis.maxScore * 0.2; // 20% weight
        }

        // 6. VirusTotal Scan (for URLs)
        if (urls.length <= 3) { // Limit to avoid rate limits
          const vtResults = await virusTotalService.scanMultipleURLs(urls);
          analysis.checks.virustotal = vtResults;
          
          if (vtResults.hasThreat) {
            analysis.threatScore += vtResults.maxThreatScore * 0.3; // 30% weight
          }
        }
      } else {
        analysis.checks.links = { urlCount: 0, hasSuspiciousLinks: false };
      }

      // Calculate final threat score (0-100)
      analysis.threatScore = Math.min(100, Math.round(analysis.threatScore));
      analysis.isPhishing = analysis.threatScore >= 50;
      analysis.confidence = analysis.threatScore / 100;

      // Save analysis to database
      const [result] = await pool.query(
        `INSERT INTO analyzed_emails (
          user_id, subject, body, sender_email, sender_name,
          threat_score, threat_level, detected_threats, ml_prediction,
          has_char_substitution, has_name_mismatch,
          virustotal_results, analyzed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          userId,
          subject,
          body,
          sender,
          senderName,
          analysis.threatScore,
          analysis.threatScore >= 70 ? 'critical' : analysis.threatScore >= 50 ? 'dangerous' : analysis.threatScore >= 30 ? 'suspicious' : 'safe',
          JSON.stringify(analysis.checks),
          analysis.checks.ml_prediction?.threat_score || 0,
          charDetection.hasSubstitution || senderCheck.isSpoofed,
          nameCheck.hasMismatch,
          JSON.stringify(analysis.checks.virustotal || {})
        ]
      );

      const emailId = result.insertId;
      analysis.emailId = emailId;

      // Automated Response System
      if (automatedResponseService.shouldTrigger(analysis.threatScore)) {
        const containment = await automatedResponseService.executeContainment(
          { id: emailId, ...emailData, sender_domain: senderDomain, threat_score: analysis.threatScore },
          userId
        );
        analysis.automatedResponse = containment;
      }

      // Calculate analysis time
      const analysisTime = Date.now() - analysisStart;

      res.json({
        success: true,
        emailId,
        threatScore: analysis.threatScore,
        isPhishing: analysis.isPhishing,
        confidence: analysis.confidence,
        analysisTimeMs: analysisTime,
        checks: analysis.checks,
        automatedResponse: analysis.automatedResponse,
        recommendation: this.getRecommendation(analysis.threatScore)
      });

    } catch (error) {
      console.error('Email analysis error:', error);
      res.status(500).json({ 
        error: 'Analysis failed',
        message: error.message 
      });
    }
  }

  /**
   * Get recommendation based on threat score
   */
  getRecommendation(threatScore) {
    if (threatScore >= 90) {
      return {
        level: 'critical',
        action: 'DELETE IMMEDIATELY',
        message: 'This email is highly likely to be a phishing attack. It has been quarantined and the sender has been blocked.'
      };
    } else if (threatScore >= 70) {
      return {
        level: 'high',
        action: 'DELETE',
        message: 'This email shows strong indicators of phishing. Avoid clicking any links or downloading attachments.'
      };
    } else if (threatScore >= 50) {
      return {
        level: 'medium',
        action: 'CAUTION',
        message: 'This email contains suspicious elements. Verify the sender before taking any action.'
      };
    } else if (threatScore >= 30) {
      return {
        level: 'low',
        action: 'REVIEW',
        message: 'This email has some suspicious characteristics. Proceed with caution.'
      };
    } else {
      return {
        level: 'safe',
        action: 'SAFE',
        message: 'This email appears to be legitimate based on our analysis.'
      };
    }
  }

  /**
   * Get analysis history for user
   */
  async getHistory(req, res) {
    try {
      const userId = req.user.userId;
      const limit = parseInt(req.query.limit) || 50;
      const offset = parseInt(req.query.offset) || 0;

      const [emails] = await pool.query(
        `SELECT id, subject, sender_email as sender, threat_score, threat_level, 
         analyzed_at 
         FROM analyzed_emails 
         WHERE user_id = ? 
         ORDER BY analyzed_at DESC 
         LIMIT ? OFFSET ?`,
        [userId, limit, offset]
      );

      const [countResult] = await pool.query(
        'SELECT COUNT(*) as total FROM analyzed_emails WHERE user_id = ?',
        [userId]
      );

      res.json({
        emails,
        total: countResult[0].total,
        limit,
        offset
      });

    } catch (error) {
      console.error('History error:', error);
      res.status(500).json({ error: 'Failed to get history' });
    }
  }

  /**
   * Get detailed analysis for specific email
   */
  async getEmailDetails(req, res) {
    try {
      const { id } = req.params;
      const userId = req.user.userId;

      const [emails] = await pool.query(
        'SELECT * FROM analyzed_emails WHERE id = ? AND user_id = ?',
        [id, userId]
      );

      if (emails.length === 0) {
        return res.status(404).json({ error: 'Email not found' });
      }

      const email = emails[0];
      
      // Parse JSON fields
      if (email.detected_threats) {
        email.detected_threats = JSON.parse(email.detected_threats);
      }
      if (email.virustotal_results) {
        email.virustotal_results = JSON.parse(email.virustotal_results);
      }

      res.json({ email });

    } catch (error) {
      console.error('Email details error:', error);
      res.status(500).json({ error: 'Failed to get email details' });
    }
  }
}

module.exports = new EmailController();
