const fs = require('fs');
const path = require('path');

/**
 * Deduplication engine that maintains a window of last 20 processed CVEs
 */
class Deduplicator {
  constructor(stateFilePath = 'data/state.json') {
    this.stateFilePath = stateFilePath;
    this.maxHistory = 1000;
    this.processedCVEs = this.loadState();
  }
  
  /**
   * Load processed CVEs from state file
   * @returns {Array<string>} Array of processed CVE IDs
   */
  loadState() {
    try {
      if (fs.existsSync(this.stateFilePath)) {
        const data = fs.readFileSync(this.stateFilePath, 'utf8');
        const state = JSON.parse(data);
        return state.processedCVEs || [];
      }
    } catch (error) {
      console.log('No existing state file found or error reading it, starting fresh');
    }
    return [];
  }
  
  /**
   * Save processed CVEs to state file
   */
  saveState() {
    try {
      const dir = path.dirname(this.stateFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      const state = {
        processedCVEs: this.processedCVEs,
        lastUpdate: new Date().toISOString()
      };
      
      fs.writeFileSync(this.stateFilePath, JSON.stringify(state, null, 2));
      console.log(`State saved: ${this.processedCVEs.length} CVEs tracked`);
    } catch (error) {
      console.error('Error saving state:', error.message);
    }
  }
  
  /**
   * Filter out already processed CVEs
   * @param {Array} cves - Array of CVE objects
   * @returns {Array} Array of new CVEs that haven't been processed
   */
  filterNewCVEs(cves) {
    // Validate input
    if (!Array.isArray(cves)) {
      throw new Error('CVEs must be an array');
    }
    
    const newCVEs = cves.filter(cve => {
      if (!cve || !cve.id) {
        console.warn('Skipping invalid CVE entry without id');
        return false;
      }
      return !this.processedCVEs.includes(cve.id);
    });
    console.log(`Filtered ${newCVEs.length} new CVEs out of ${cves.length} total`);
    return newCVEs;
  }
  
  /**
   * Mark CVEs as processed and update the tracking list
   * @param {Array} cves - Array of CVE objects to mark as processed
   */
  markAsProcessed(cves) {
    // Validate input
    if (!Array.isArray(cves)) {
      throw new Error('CVEs must be an array');
    }
    
    const cveIds = cves
      .filter(cve => cve && cve.id)
      .map(cve => cve.id);
    
    if (cveIds.length === 0) {
      console.log('No valid CVE IDs to mark as processed');
      return;
    }
    
    // Add new CVE IDs to the beginning of the list
    this.processedCVEs = [...cveIds, ...this.processedCVEs];
    
    // Keep only the last N CVEs
    this.processedCVEs = this.processedCVEs.slice(0, this.maxHistory);
    
    console.log(`Marked ${cveIds.length} CVEs as processed`);
    
    // Save the updated state
    this.saveState();
  }
  
  /**
   * Check if a specific CVE has been processed
   * @param {string} cveId - CVE ID to check
   * @returns {boolean} True if CVE has been processed
   */
  isProcessed(cveId) {
    return this.processedCVEs.includes(cveId);
  }
  
  /**
   * Get the list of all processed CVEs
   * @returns {Array<string>} Array of processed CVE IDs
   */
  getProcessedCVEs() {
    return [...this.processedCVEs];
  }
}

module.exports = { Deduplicator };
