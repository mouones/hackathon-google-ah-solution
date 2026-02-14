/**
 * Email Formality Detection Service
 * Analyzes email professionalism and structure
 */

class FormalityService {
  constructor() {
    // Professional email indicators
    this.professionalDomains = [
      'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
      'live.com', 'icloud.com', 'protonmail.com', 'aol.com'
    ];

    this.corporateDomainPatterns = [
      /\.com$/, /\.org$/, /\.net$/, /\.edu$/, /\.gov$/
    ];

    // Formal greetings and closings
    this.formalGreetings = [
      'dear', 'hello', 'greetings', 'good morning', 'good afternoon', 'good evening'
    ];

    this.formalClosings = [
      'sincerely', 'regards', 'best regards', 'kind regards', 
      'respectfully', 'thank you', 'thanks', 'best'
    ];

    // Unprofessional indicators
    this.urgencyWords = [
      'urgent', 'immediately', 'act now', 'limited time', 'expire',
      'suspended', 'verify now', 'confirm now', 'click here', 'hurry'
    ];

    this.spamWords = [
      'congratulations', 'winner', 'free', 'prize', 'claim',
      'lottery', 'million dollars', 'inheritance', 'nigerian prince'
    ];
  }

  /**
   * Analyze email formality and professionalism
   * @param {Object} email - Email data { subject, body, sender }
   * @returns {Object} - Formality analysis
   */
  analyze(email) {
    const { subject = '', body = '', sender = '' } = email;
    const text = `${subject} ${body}`.toLowerCase();
    
    const results = {
      formalityScore: 0,
      isProfessional: false,
      hasGreeting: false,
      hasClosing: false,
      hasSignature: false,
      domainType: 'unknown',
      issues: [],
      details: {}
    };

    // Check domain professionalism
    results.domainType = this.analyzeDomain(sender);
    if (results.domainType === 'corporate') {
      results.formalityScore += 25;
    } else if (results.domainType === 'free_email') {
      results.formalityScore += 10;
    }

    // Check for greeting
    results.hasGreeting = this.formalGreetings.some(greeting => 
      text.includes(greeting)
    );
    if (results.hasGreeting) {
      results.formalityScore += 15;
    }

    // Check for closing
    results.hasClosing = this.formalClosings.some(closing => 
      text.includes(closing)
    );
    if (results.hasClosing) {
      results.formalityScore += 15;
    }

    // Check for signature (name after closing)
    results.hasSignature = this.detectSignature(body);
    if (results.hasSignature) {
      results.formalityScore += 15;
    }

    // Check email structure
    const structureScore = this.analyzeStructure(body);
    results.formalityScore += structureScore;
    results.details.structure = structureScore;

    // Check for urgency (negative for professionalism)
    const urgencyCount = this.urgencyWords.reduce((count, word) => 
      count + (text.split(word).length - 1), 0
    );
    if (urgencyCount > 0) {
      results.formalityScore -= urgencyCount * 5;
      results.issues.push({
        type: 'high_urgency',
        count: urgencyCount,
        description: 'Contains urgency language uncommon in professional emails'
      });
    }

    // Check for spam words (very negative)
    const spamCount = this.spamWords.reduce((count, word) => 
      count + (text.split(word).length - 1), 0
    );
    if (spamCount > 0) {
      results.formalityScore -= spamCount * 10;
      results.issues.push({
        type: 'spam_language',
        count: spamCount,
        description: 'Contains spam/scam keywords'
      });
    }

    // Check grammar quality (simplified)
    const grammarScore = this.analyzeGrammar(body);
    results.formalityScore += grammarScore;
    results.details.grammar = grammarScore;

    // Normalize score to 0-100
    results.formalityScore = Math.max(0, Math.min(100, results.formalityScore));
    results.isProfessional = results.formalityScore >= 60;

    // High urgency + low formality = likely phishing
    if (urgencyCount > 2 && results.formalityScore < 50) {
      results.issues.push({
        type: 'phishing_pattern',
        description: 'High urgency with unprofessional format suggests phishing'
      });
    }

    return results;
  }

  /**
   * Analyze sender domain type
   * @param {string} email - Sender email
   * @returns {string} - Domain type
   */
  analyzeDomain(email) {
    if (!email) return 'unknown';
    
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return 'invalid';

    if (this.professionalDomains.includes(domain)) {
      return 'free_email';
    }

    if (this.corporateDomainPatterns.some(pattern => pattern.test(domain))) {
      // Not in free email list but has corporate TLD
      return 'corporate';
    }

    return 'unknown';
  }

  /**
   * Detect signature in email body
   * @param {string} body - Email body
   * @returns {boolean} - Has signature
   */
  detectSignature(body) {
    // Look for name pattern after closing
    const signaturePattern = /(?:sincerely|regards|best|thanks),?\s*\n?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/i;
    return signaturePattern.test(body);
  }

  /**
   * Analyze email structure
   * @param {string} body - Email body
   * @returns {number} - Structure score (0-20)
   */
  analyzeStructure(body) {
    let score = 0;

    // Has paragraphs (multiple line breaks)
    if (body.split('\n\n').length > 1) {
      score += 5;
    }

    // Reasonable length (not too short, not too long)
    const wordCount = body.split(/\s+/).length;
    if (wordCount >= 20 && wordCount <= 500) {
      score += 5;
    }

    // Has proper punctuation
    if (body.includes('.') && body.includes(',')) {
      score += 5;
    }

    // Not all caps
    const capsRatio = (body.match(/[A-Z]/g) || []).length / body.length;
    if (capsRatio < 0.3) {
      score += 5;
    }

    return score;
  }

  /**
   * Analyze grammar quality (simplified)
   * @param {string} text - Text to analyze
   * @returns {number} - Grammar score (0-10)
   */
  analyzeGrammar(text) {
    let score = 10;

    // Check for excessive exclamation marks
    const exclamationCount = (text.match(/!/g) || []).length;
    if (exclamationCount > 3) {
      score -= 3;
    }

    // Check for excessive question marks
    const questionCount = (text.match(/\?/g) || []).length;
    if (questionCount > 5) {
      score -= 2;
    }

    // Check for proper sentence structure (simplified)
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    const avgSentenceLength = sentences.reduce((sum, s) => 
      sum + s.split(/\s+/).length, 0) / sentences.length;
    
    if (avgSentenceLength > 5 && avgSentenceLength < 30) {
      score += 5;
    }

    return Math.max(0, score);
  }
}

module.exports = new FormalityService();
