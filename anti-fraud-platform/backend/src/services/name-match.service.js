/**
 * Name Mismatch Detection Service
 * Detects when sender name doesn't match signature name
 */

class NameMatchService {
  /**
   * Extract name from email signature
   * @param {string} body - Email body
   * @returns {string|null} - Extracted name or null
   */
  extractSignatureName(body) {
    if (!body) return null;

    // Common signature patterns
    const patterns = [
      /(?:sincerely|regards|best regards|kind regards|respectfully|thanks|thank you|best),?\s*\n?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})/i,
      /\n([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\s*$/,  // Name at end
      /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})\s*\n/,  // Name at start (rare)
    ];

    for (const pattern of patterns) {
      const match = body.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }

    return null;
  }

  /**
   * Extract name from "From" field
   * @param {string} senderName - Sender display name
   * @returns {string|null} - Cleaned name
   */
  extractSenderName(senderName) {
    if (!senderName) return null;

    // Remove email addresses in brackets
    let cleaned = senderName.replace(/<[^>]+>/g, '').trim();
    
    // Remove quotes
    cleaned = cleaned.replace(/['"]/g, '').trim();
    
    return cleaned || null;
  }

  /**
   * Calculate similarity between two names
   * @param {string} name1 - First name
   * @param {string} name2 - Second name
   * @returns {number} - Similarity score (0-100)
   */
  calculateSimilarity(name1, name2) {
    if (!name1 || !name2) return 0;

    const n1 = name1.toLowerCase().trim();
    const n2 = name2.toLowerCase().trim();

    // Exact match
    if (n1 === n2) return 100;

    // Split into parts
    const parts1 = n1.split(/\s+/);
    const parts2 = n2.split(/\s+/);

    // Check if any part matches
    const matchingParts = parts1.filter(part1 => 
      parts2.some(part2 => part2.includes(part1) || part1.includes(part2))
    );

    if (matchingParts.length > 0) {
      return Math.round((matchingParts.length / Math.max(parts1.length, parts2.length)) * 100);
    }

    // Levenshtein distance
    const distance = this.levenshteinDistance(n1, n2);
    const maxLength = Math.max(n1.length, n2.length);
    const similarity = ((maxLength - distance) / maxLength) * 100;

    return Math.round(similarity);
  }

  /**
   * Calculate Levenshtein distance between two strings
   * @param {string} str1 - First string
   * @param {string} str2 - Second string
   * @returns {number} - Edit distance
   */
  levenshteinDistance(str1, str2) {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,  // substitution
            matrix[i][j - 1] + 1,      // insertion
            matrix[i - 1][j] + 1       // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Analyze name mismatch between sender and signature
   * @param {Object} email - Email data { sender, senderName, body }
   * @returns {Object} - Mismatch analysis
   */
  analyze(email) {
    const { sender, senderName, body } = email;

    const result = {
      hasMismatch: false,
      severity: 'none',
      similarityScore: 100,
      senderName: null,
      signatureName: null,
      details: null
    };

    // Extract names
    result.senderName = this.extractSenderName(senderName);
    result.signatureName = this.extractSignatureName(body);

    // If no signature found, can't determine mismatch
    if (!result.signatureName) {
      result.details = 'No signature found in email body';
      return result;
    }

    // If no sender name, use email address
    if (!result.senderName && sender) {
      result.senderName = sender.split('@')[0].replace(/[._-]/g, ' ');
    }

    if (!result.senderName) {
      result.details = 'No sender name available';
      return result;
    }

    // Calculate similarity
    result.similarityScore = this.calculateSimilarity(
      result.senderName,
      result.signatureName
    );

    // Determine mismatch and severity
    if (result.similarityScore < 30) {
      result.hasMismatch = true;
      result.severity = 'critical';
      result.details = `Sender name "${result.senderName}" completely different from signature "${result.signatureName}"`;
    } else if (result.similarityScore < 60) {
      result.hasMismatch = true;
      result.severity = 'high';
      result.details = `Sender name "${result.senderName}" significantly different from signature "${result.signatureName}"`;
    } else if (result.similarityScore < 80) {
      result.hasMismatch = true;
      result.severity = 'medium';
      result.details = `Sender name "${result.senderName}" somewhat different from signature "${result.signatureName}"`;
    } else {
      result.hasMismatch = false;
      result.severity = 'none';
      result.details = `Names match closely (${result.similarityScore}% similar)`;
    }

    return result;
  }

  /**
   * Quick check if email has suspicious name mismatch
   * @param {Object} email - Email data
   * @returns {boolean} - True if suspicious
   */
  isSuspicious(email) {
    const result = this.analyze(email);
    return result.hasMismatch && (result.severity === 'critical' || result.severity === 'high');
  }
}

module.exports = new NameMatchService();
