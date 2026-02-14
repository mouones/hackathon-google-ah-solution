/**
 * Character Substitution Detection Service
 * Detects visual spoofing attacks like "rn" vs "m", "vv" vs "w"
 */

class CharDetectionService {
  constructor() {
    // Common character substitution patterns
    this.substitutionPatterns = [
      { pattern: /rn/gi, fake: 'rn', real: 'm', description: 'rn looks like m' },
      { pattern: /vv/gi, fake: 'vv', real: 'w', description: 'vv looks like w' },
      { pattern: /cl/gi, fake: 'cl', real: 'd', description: 'cl looks like d' },
      { pattern: /\/\\/gi, fake: '/\\', real: 'A', description: '/\\ looks like A' },
    ];

    // Unicode lookalike characters (homoglyphs)
    this.homoglyphs = [
      { char: 'а', lookalike: 'a', script: 'Cyrillic' },  // Cyrillic 'a'
      { char: 'е', lookalike: 'e', script: 'Cyrillic' },  // Cyrillic 'e'
      { char: 'о', lookalike: 'o', script: 'Cyrillic' },  // Cyrillic 'o'
      { char: 'р', lookalike: 'p', script: 'Cyrillic' },  // Cyrillic 'p'
      { char: 'с', lookalike: 'c', script: 'Cyrillic' },  // Cyrillic 'c'
      { char: 'у', lookalike: 'y', script: 'Cyrillic' },  // Cyrillic 'y'
      { char: 'х', lookalike: 'x', script: 'Cyrillic' },  // Cyrillic 'x'
      { char: 'ο', lookalike: 'o', script: 'Greek' },      // Greek omicron
      { char: 'ρ', lookalike: 'p', script: 'Greek' },      // Greek rho
      { char: '0', lookalike: 'O', script: 'Number' },     // Zero vs O
      { char: '1', lookalike: 'l', script: 'Number' },     // One vs l
    ];
  }

  /**
   * Analyze text for character substitution patterns
   * @param {string} text - Text to analyze
   * @returns {Object} - Detection results
   */
  detect(text) {
    if (!text) {
      return {
        hasSubstitution: false,
        matches: [],
        score: 0,
        details: []
      };
    }

    const matches = [];
    const details = [];

    // Check ASCII substitution patterns
    this.substitutionPatterns.forEach(({ pattern, fake, real, description }) => {
      const found = text.match(pattern);
      if (found) {
        matches.push(...found);
        details.push({
          type: 'ascii_substitution',
          pattern: fake,
          shouldBe: real,
          description,
          count: found.length,
          positions: this.findPositions(text, pattern)
        });
      }
    });

    // Check Unicode homoglyphs
    this.homoglyphs.forEach(({ char, lookalike, script }) => {
      if (text.includes(char)) {
        const count = (text.match(new RegExp(char, 'g')) || []).length;
        matches.push(char);
        details.push({
          type: 'unicode_homoglyph',
          character: char,
          lookalike,
          script,
          count,
          positions: this.findPositions(text, new RegExp(char, 'g'))
        });
      }
    });

    // Calculate risk score (0-100)
    const score = Math.min(100, matches.length * 15);

    return {
      hasSubstitution: matches.length > 0,
      matches,
      score,
      details,
      totalCount: matches.length
    };
  }

  /**
   * Find all positions of a pattern in text
   * @param {string} text - Text to search
   * @param {RegExp} pattern - Pattern to find
   * @returns {Array} - Array of positions
   */
  findPositions(text, pattern) {
    const positions = [];
    let match;
    const regex = new RegExp(pattern, 'g');
    
    while ((match = regex.exec(text)) !== null) {
      positions.push(match.index);
    }
    
    return positions;
  }

  /**
   * Analyze sender email/domain for substitutions
   * @param {string} email - Email address to check
   * @param {Array} knownBrands - List of known brand names
   * @returns {Object} - Analysis result
   */
  analyzeSenderEmail(email, knownBrands = []) {
    if (!email) {
      return { isSpoofed: false, score: 0 };
    }

    const domain = email.split('@')[1] || '';
    const results = {
      isSpoofed: false,
      score: 0,
      suspiciousDomain: false,
      brandImpersonation: null,
      details: []
    };

    // Check domain for substitutions
    const domainCheck = this.detect(domain);
    if (domainCheck.hasSubstitution) {
      results.isSpoofed = true;
      results.suspiciousDomain = true;
      results.score += domainCheck.score;
      results.details.push(...domainCheck.details);
    }

    // Check for brand impersonation
    knownBrands.forEach(brand => {
      const normalizedDomain = domain.toLowerCase();
      const normalizedBrand = brand.toLowerCase();
      
      // Check if domain contains brand-like string with substitutions
      if (normalizedDomain.includes(normalizedBrand.replace(/m/g, 'rn')) ||
          normalizedDomain.includes(normalizedBrand.replace(/w/g, 'vv')) ||
          normalizedDomain.includes(normalizedBrand.replace(/d/g, 'cl'))) {
        results.isSpoofed = true;
        results.brandImpersonation = brand;
        results.score += 30;
        results.details.push({
          type: 'brand_impersonation',
          brand,
          domain,
          description: `Domain appears to impersonate ${brand} using character substitution`
        });
      }
    });

    results.score = Math.min(100, results.score);
    return results;
  }
}

module.exports = new CharDetectionService();
