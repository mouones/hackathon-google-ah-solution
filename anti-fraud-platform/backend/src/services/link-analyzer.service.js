/**
 * Advanced Link Analyzer Service
 * Performs comprehensive URL analysis including:
 * - Domain age checking (WHOIS)
 * - Subdomain analysis
 * - Brand impersonation detection
 * - Redirect behavior analysis
 * - Ephemeral domain detection
 */

const axios = require('axios');
const whois = require('whois');
const { promisify } = require('util');

const whoisLookup = promisify(whois.lookup);

class LinkAnalyzerService {
  constructor() {
    // Known brands to check for impersonation
    this.knownBrands = [
      'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
      'netflix', 'ebay', 'instagram', 'twitter', 'linkedin', 'bank',
      'wells fargo', 'chase', 'citibank', 'americanexpress', 'visa',
      'mastercard', 'usps', 'fedex', 'ups', 'dhl'
    ];

    // Ephemeral/free domain TLDs
    this.ephemeralTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.club',
      '.online', '.site', '.website', '.space', '.tech', '.store'
    ];

    // Suspicious keywords in subdomains/domains
    this.suspiciousKeywords = [
      'verify', 'secure', 'account', 'update', 'confirm', 'login',
      'signin', 'banking', 'support', 'service', 'help', 'admin',
      'security', 'suspended', 'locked', 'alert', 'notification'
    ];
  }

  /**
   * Extract all URLs from text
   * @param {string} text - Text to extract URLs from
   * @returns {Array} - Array of URLs
   */
  extractURLs(text) {
    const urlPattern = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/gi;
    return text.match(urlPattern) || [];
  }

  /**
   * Parse URL into components
   * @param {string} url - URL to parse
   * @returns {Object} - URL components
   */
  parseURL(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      const parts = hostname.split('.');
      
      // Extract domain and subdomains
      let domain, tld, subdomains;
      
      if (parts.length >= 2) {
        tld = '.' + parts[parts.length - 1];
        domain = parts[parts.length - 2] + tld;
        subdomains = parts.slice(0, -2);
      }

      return {
        full: url,
        protocol: urlObj.protocol,
        hostname,
        domain: domain || hostname,
        tld: tld || '',
        subdomains: subdomains || [],
        path: urlObj.pathname,
        hasQueryParams: urlObj.search.length > 0,
        hasFragment: urlObj.hash.length > 0
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Check domain age using WHOIS
   * @param {string} domain - Domain to check
   * @returns {Promise<Object>} - Domain age info
   */
  async checkDomainAge(domain) {
    try {
      const data = await whoisLookup(domain);
      
      // Extract creation date (simplified - real implementation would parse more carefully)
      const creationMatch = data.match(/Creation Date:\s*(\d{4}-\d{2}-\d{2})/i) ||
                           data.match(/created:\s*(\d{4}-\d{2}-\d{2})/i) ||
                           data.match(/registered:\s*(\d{4}-\d{2}-\d{2})/i);
      
      if (creationMatch) {
        const creationDate = new Date(creationMatch[1]);
        const now = new Date();
        const ageInDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));
        
        return {
          success: true,
          creationDate: creationMatch[1],
          ageInDays,
          isNew: ageInDays < 30,
          isRecent: ageInDays < 90,
          suspicionLevel: ageInDays < 30 ? 'high' : ageInDays < 90 ? 'medium' : 'low'
        };
      }

      return {
        success: false,
        error: 'Creation date not found in WHOIS data'
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Analyze subdomain structure
   * @param {Object} urlData - Parsed URL data
   * @returns {Object} - Subdomain analysis
   */
  analyzeSubdomains(urlData) {
    if (!urlData || !urlData.subdomains) {
      return { score: 0, issues: [] };
    }

    const issues = [];
    let score = 0;

    // Multiple subdomain levels (suspicious)
    if (urlData.subdomains.length > 2) {
      score += 20;
      issues.push({
        type: 'multiple_subdomains',
        count: urlData.subdomains.length,
        description: 'Excessive subdomain levels often indicate phishing'
      });
    }

    // Brand name in subdomain but not main domain
    const subdomainStr = urlData.subdomains.join('.');
    const brandInSubdomain = this.knownBrands.find(brand => 
      subdomainStr.includes(brand)
    );

    if (brandInSubdomain && !urlData.domain.includes(brandInSubdomain)) {
      score += 40;
      issues.push({
        type: 'brand_in_subdomain',
        brand: brandInSubdomain,
        description: `Brand "${brandInSubdomain}" in subdomain suggests impersonation`
      });
    }

    // Suspicious keywords in subdomain
    const suspiciousInSubdomain = this.suspiciousKeywords.filter(keyword =>
      subdomainStr.includes(keyword)
    );

    if (suspiciousInSubdomain.length > 0) {
      score += suspiciousInSubdomain.length * 15;
      issues.push({
        type: 'suspicious_subdomain_keywords',
        keywords: suspiciousInSubdomain,
        description: 'Subdomain contains phishing-related keywords'
      });
    }

    return { score: Math.min(100, score), issues };
  }

  /**
   * Detect brand impersonation
   * @param {Object} urlData - Parsed URL data
   * @returns {Object} - Brand impersonation analysis
   */
  detectBrandImpersonation(urlData) {
    if (!urlData) {
      return { score: 0, impersonating: null };
    }

    const fullDomain = urlData.hostname.toLowerCase();
    
    for (const brand of this.knownBrands) {
      const brandNormalized = brand.replace(/\s+/g, '');
      
      // Check for typosquatting patterns
      const patterns = [
        fullDomain.includes(brandNormalized + '-'),
        fullDomain.includes(brandNormalized + '.'),
        fullDomain.includes('secure' + brandNormalized),
        fullDomain.includes(brandNormalized + 'secure'),
        fullDomain.includes(brandNormalized + 'support'),
        fullDomain.includes(brandNormalized + 'help'),
        fullDomain.includes(brandNormalized + 'login'),
        fullDomain.includes(brandNormalized + 'verify'),
      ];

      if (patterns.some(p => p) && !fullDomain.endsWith(brandNormalized + urlData.tld)) {
        return {
          score: 50,
          impersonating: brand,
          pattern: 'typosquatting',
          description: `Domain appears to impersonate ${brand}`
        };
      }
    }

    return { score: 0, impersonating: null };
  }

  /**
   * Check if domain uses ephemeral TLD
   * @param {Object} urlData - Parsed URL data
   * @returns {Object} - Ephemeral domain check
   */
  checkEphemeralDomain(urlData) {
    if (!urlData || !urlData.tld) {
      return { isEphemeral: false, score: 0 };
    }

    const isEphemeral = this.ephemeralTLDs.includes(urlData.tld.toLowerCase());

    return {
      isEphemeral,
      score: isEphemeral ? 30 : 0,
      description: isEphemeral ? `Uses ephemeral TLD ${urlData.tld}` : null
    };
  }

  /**
   * Analyze URL structure for suspicious patterns
   * @param {Object} urlData - Parsed URL data
   * @returns {Object} - Structure analysis
   */
  analyzeURLStructure(urlData) {
    if (!urlData) {
      return { score: 0, issues: [] };
    }

    const issues = [];
    let score = 0;

    // IP address instead of domain
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(urlData.hostname)) {
      score += 40;
      issues.push({
        type: 'ip_address',
        description: 'Using IP address instead of domain name'
      });
    }

    // Excessive URL length
    if (urlData.full.length > 100) {
      score += 15;
      issues.push({
        type: 'excessive_length',
        length: urlData.full.length,
        description: 'Unusually long URL often indicates phishing'
      });
    }

    // @ symbol in URL (can hide real domain)
    if (urlData.full.includes('@')) {
      score += 30;
      issues.push({
        type: 'at_symbol',
        description: '@ symbol can obscure actual destination'
      });
    }

    // Excessive hyphens in domain
    const hyphenCount = (urlData.hostname.match(/-/g) || []).length;
    if (hyphenCount > 3) {
      score += 20;
      issues.push({
        type: 'excessive_hyphens',
        count: hyphenCount,
        description: 'Multiple hyphens often indicate fake domains'
      });
    }

    return { score: Math.min(100, score), issues };
  }

  /**
   * Check redirect behavior
   * @param {string} url - URL to check
   * @returns {Promise<Object>} - Redirect analysis
   */
  async checkRedirects(url) {
    try {
      const response = await axios.get(url, {
        maxRedirects: 5,
        timeout: 5000,
        validateStatus: () => true
      });

      const redirectCount = response.request._redirectable?._redirectCount || 0;
      const finalURL = response.request.res?.responseUrl || url;

      const initialDomain = new URL(url).hostname;
      const finalDomain = new URL(finalURL).hostname;
      const domainChanged = initialDomain !== finalDomain;

      return {
        success: true,
        redirectCount,
        finalURL,
        domainChanged,
        score: redirectCount > 2 ? 25 : redirectCount > 0 && domainChanged ? 35 : 0,
        suspicious: redirectCount > 2 || domainChanged
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        score: 0
      };
    }
  }

  /**
   * Comprehensive URL analysis
   * @param {string} url - URL to analyze
   * @returns {Promise<Object>} - Complete analysis
   */
  async analyzeURL(url) {
    const urlData = this.parseURL(url);
    if (!urlData) {
      return {
        success: false,
        error: 'Invalid URL'
      };
    }

    const analysis = {
      url,
      parsed: urlData,
      totalScore: 0,
      riskLevel: 'low',
      checks: {}
    };

    // Run all checks
    analysis.checks.subdomain = this.analyzeSubdomains(urlData);
    analysis.checks.brandImpersonation = this.detectBrandImpersonation(urlData);
    analysis.checks.ephemeralDomain = this.checkEphemeralDomain(urlData);
    analysis.checks.urlStructure = this.analyzeURLStructure(urlData);

    // Async checks
    try {
      analysis.checks.domainAge = await this.checkDomainAge(urlData.domain);
      if (analysis.checks.domainAge.isNew) {
        analysis.totalScore += 30;
      }
    } catch (error) {
      analysis.checks.domainAge = { error: error.message };
    }

    // Calculate total score
    analysis.totalScore += analysis.checks.subdomain.score;
    analysis.totalScore += analysis.checks.brandImpersonation.score;
    analysis.checks.ephemeralDomain.score;
    analysis.totalScore += analysis.checks.urlStructure.score;

    // Determine risk level
    if (analysis.totalScore >= 70) {
      analysis.riskLevel = 'critical';
    } else if (analysis.totalScore >= 50) {
      analysis.riskLevel = 'high';
    } else if (analysis.totalScore >= 30) {
      analysis.riskLevel = 'medium';
    } else {
      analysis.riskLevel = 'low';
    }

    return analysis;
  }

  /**
   * Analyze all URLs in text
   * @param {string} text - Text containing URLs
   * @returns {Promise<Object>} - Analysis of all URLs
   */
  async analyzeAllURLs(text) {
    const urls = this.extractURLs(text);
    
    if (urls.length === 0) {
      return {
        urlCount: 0,
        urls: [],
        maxScore: 0,
        hasSuspiciousLinks: false
      };
    }

    const analyses = await Promise.all(
      urls.map(url => this.analyzeURL(url).catch(err => ({ 
        url, 
        error: err.message,
        totalScore: 0 
      })))
    );

    const maxScore = Math.max(...analyses.map(a => a.totalScore || 0));

    return {
      urlCount: urls.length,
      urls: analyses,
      maxScore,
      hasSuspiciousLinks: maxScore >= 50
    };
  }
}

module.exports = new LinkAnalyzerService();
