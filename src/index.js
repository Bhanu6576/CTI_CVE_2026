const { searchCVEs } = require('./cve-search');
const { Deduplicator } = require('./deduplication');
const { generateAdvisories } = require('./advisory-generator');
const { sendAdvisoriesToTeams } = require('./teams-notifier');
const fs = require('fs');
const path = require('path');

async function main() {
  try {
    // Validate and sanitize environment variables
    const apiKey = process.env.NVD_API_KEY || null;
    const cvssThresholdInput = process.env.CVSS_THRESHOLD;
    let cvssThreshold = 8.0;
    
    if (cvssThresholdInput) {
      cvssThreshold = parseFloat(cvssThresholdInput);
      if (isNaN(cvssThreshold) || cvssThreshold < 0 || cvssThreshold > 10) {
        console.error('Invalid CVSS_THRESHOLD. Must be between 0 and 10. Using default: 8.0');
        cvssThreshold = 8.0;
      }
    }
    
    const teamsWebhook = process.env.TEAMS_WEBHOOK_URL || null;
    
    // Validate Teams webhook URL format if provided
    if (teamsWebhook) {
      try {
        new URL(teamsWebhook);
      } catch (e) {
        console.error('Invalid TEAMS_WEBHOOK_URL format. Skipping notifications.');
      }
    }
    
    console.log(`Starting CVE automation with threshold: ${cvssThreshold}`);
    
    // Search for CVEs
    const cves = await searchCVEs(apiKey, cvssThreshold);
    console.log(`Found ${cves.length} CVEs`);
    
    if (cves.length === 0) {
      console.log('No CVEs found matching criteria');
      return;
    }
    
    // Filter out duplicates
    const deduplicator = new Deduplicator('data/state.json');
    const newCVEs = deduplicator.filterNewCVEs(cves);
    
    if (newCVEs.length === 0) {
      console.log('No new CVEs to process');
      return;
    }
    
    // Generate advisories
    const advisories = generateAdvisories(newCVEs);
    
    if (advisories.length === 0) {
      console.log('No valid advisories generated');
      return;
    }
    
    // Save advisories to disk
    const advisoriesDir = 'data/advisories';
    try {
      if (!fs.existsSync(advisoriesDir)) {
        fs.mkdirSync(advisoriesDir, { recursive: true });
      }
      
      advisories.forEach(advisory => {
        try {
          const filename = path.join(advisoriesDir, `${advisory.id}.json`);
          fs.writeFileSync(filename, JSON.stringify(advisory, null, 2));
        } catch (fileError) {
          console.error(`Failed to save advisory ${advisory.id}: ${fileError.message}`);
        }
      });
    } catch (dirError) {
      console.error(`Failed to create advisories directory: ${dirError.message}`);
    }
    
    // Send to Teams
    if (teamsWebhook) {
      const results = await sendAdvisoriesToTeams(teamsWebhook, advisories);
      console.log(`Teams notification results:`, results);
    } else {
      console.warn('Teams webhook not configured, skipping notifications');
    }
    
    // Mark as processed
    deduplicator.markAsProcessed(newCVEs);
    
    console.log('Automation completed successfully');
  } catch (error) {
    console.error('Automation failed:', error);
    process.exit(1);
  }
}

main();
