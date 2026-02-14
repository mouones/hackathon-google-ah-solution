/**
 * VirusTotal Integration Service
 * Scans URLs for known threats using VirusTotal API
 * Free tier: 500 requests/day, 4 requests/minute
 */

const axios = require('axios');

class VirusTotalService {
  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
    this.baseURL = 'https://www.virustotal.com/api/v3';
    this.lastRequestTime = 0;
    this.minRequestInterval = 15000; // 15 seconds for free tier safety
  }

  /**
   * Rate limiting - wait if necessary
   */
  async rateLimit() {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < this.minRequestInterval) {
      const waitTime = this.minRequestInterval - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.lastRequestTime = Date.now();
  }

  /**
   * Encode URL for VirusTotal API
   * @param {string} url - URL to encode
   * @returns {string} - Base64 encoded URL
   */
  encodeURL(url) {
    return Buffer.from(url).toString('base64').replace(/=/g, '');
  }

  /**
   * Scan URL using VirusTotal
   * @param {string} url - URL to scan
   * @returns {Promise<Object>} - Scan results
   */
  async scanURL(url) {
    if (!this.apiKey || this.apiKey === 'your-virustotal-api-key-here') {
      return {
        success: false,
        error: 'VirusTotal API key not configured',
        skipped: true
      };
    }

    try {
      await this.rateLimit();

      const urlId = this.encodeURL(url);
      const response = await axios.get(`${this.baseURL}/urls/${urlId}`, {
        headers: {
          'x-apikey': this.apiKey
        },
        timeout: 10000
      });

      const stats = response.data.data.attributes.last_analysis_stats;
      const results = response.data.data.attributes.last_analysis_results;

      return {
        success: true,
        url,
        stats: {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0,
          timeout: stats.timeout || 0
        },
        totalEngines: Object.keys(results).length,
        threatScore: this.calculateThreatScore(stats),
        isThreat: (stats.malicious + stats.suspicious) > 0,
        details: results
      };
    } catch (error) {
      if (error.response?.status === 404) {
        // URL not in database, submit for analysis
        return await this.submitURL(url);
      }

      return {
        success: false,
        error: error.message,
        url
      };
    }
  }

  /**
   * Submit URL for analysis
   * @param {string} url - URL to submit
   * @returns {Promise<Object>} - Submission result
   */
  async submitURL(url) {
    if (!this.apiKey || this.apiKey === 'your-virustotal-api-key-here') {
      return {
        success: false,
        error: 'VirusTotal API key not configured',
        skipped: true
      };
    }

    try {
      await this.rateLimit();

      const formData = new URLSearchParams();
      formData.append('url', url);

      const response = await axios.post(`${this.baseURL}/urls`, formData, {
        headers: {
          'x-apikey': this.apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 10000
      });

      return {
        success: true,
        url,
        submitted: true,
        analysisId: response.data.data.id,
        message: 'URL submitted for analysis - check back later for results',
        stats: {
          malicious: 0,
          suspicious: 0,
          harmless: 0,
          undetected: 0
        },
        threatScore: 0,
        isThreat: false
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        url
      };
    }
  }

  /**
   * Calculate threat score from VirusTotal stats
   * @param {Object} stats - VirusTotal statistics
   * @returns {number} - Threat score (0-100)
   */
  calculateThreatScore(stats) {
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;

    if (total === 0) return 0;

    // Weight malicious more heavily than suspicious
    const score = ((malicious * 2 + suspicious) / (total * 2)) * 100;
    return Math.min(100, Math.round(score));
  }

  /**
   * Scan multiple URLs
   * @param {Array} urls - Array of URLs to scan
   * @returns {Promise<Object>} - Aggregated results
   */
  async scanMultipleURLs(urls) {
    if (!urls || urls.length === 0) {
      return {
        urlCount: 0,
        scanned: [],
        maxThreatScore: 0,
        hasThreat: false
      };
    }

    const results = [];
    
    for (const url of urls) {
      const result = await this.scanURL(url);
      results.push(result);
    }

    const maxThreatScore = Math.max(...results.map(r => r.threatScore || 0));
    const hasThreat = results.some(r => r.isThreat);

    return {
      urlCount: urls.length,
      scanned: results,
      maxThreatScore,
      hasThreat,
      summary: {
        malicious: results.reduce((sum, r) => sum + (r.stats?.malicious || 0), 0),
        suspicious: results.reduce((sum, r) => sum + (r.stats?.suspicious || 0), 0),
        harmless: results.reduce((sum, r) => sum + (r.stats?.harmless || 0), 0)
      }
    };
  }
}

module.exports = new VirusTotalService();
