/**
 * Generate comprehensive security advisories for CVEs
 */

/**
 * Generate a security advisory for a CVE
 * @param {Object} cve - CVE object with details
 * @returns {Object} Formatted security advisory
 */
function generateAdvisory(cve) {
  // Validate input
  if (!cve || typeof cve !== 'object') {
    throw new Error('CVE must be an object');
  }
  
  if (!cve.id) {
    throw new Error('CVE must have an id');
  }
  
  const advisory = {
    id: cve.id,
    title: `Security Advisory: ${cve.id}`,
    severity: cve.severity || 'UNKNOWN',
    cvssScore: cve.cvssScore || 0,
    cvssVector: cve.cvssVector || '',
    publishedDate: cve.publishedDate || new Date().toISOString(),
    description: cve.description || 'No description available',
    url: cve.url || `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    references: Array.isArray(cve.references) ? cve.references : [],
    summary: generateSummary(cve),
    impact: generateImpact(cve),
    remediation: generateRemediation(cve),
    timestamp: new Date().toISOString()
  };
  
  return advisory;
}

/**
 * Generate a summary for the CVE
 * @param {Object} cve - CVE object
 * @returns {string} Summary text
 */
function generateSummary(cve) {
  const severityText = getSeverityText(cve.cvssScore);
  return `${cve.id} is a ${severityText} vulnerability with a CVSS score of ${cve.cvssScore}. ${cve.description.substring(0, 200)}${cve.description.length > 200 ? '...' : ''}`;
}

/**
 * Generate impact assessment for the CVE
 * @param {Object} cve - CVE object
 * @returns {string} Impact text
 */
function generateImpact(cve) {
  const score = cve.cvssScore;
  
  if (score >= 9.0) {
    return 'CRITICAL: This vulnerability poses an immediate and severe risk to affected systems. Exploitation could lead to complete system compromise, data breach, or service disruption.';
  } else if (score >= 8.0) {
    return 'HIGH: This vulnerability presents a significant risk to affected systems. Exploitation could result in unauthorized access, data exposure, or service degradation.';
  } else if (score >= 7.0) {
    return 'MEDIUM-HIGH: This vulnerability should be addressed promptly as it may allow unauthorized access or information disclosure under certain conditions.';
  } else {
    return 'This vulnerability requires attention and should be evaluated in the context of your specific environment.';
  }
}

/**
 * Generate remediation guidance for the CVE
 * @param {Object} cve - CVE object
 * @returns {string} Remediation text
 */
function generateRemediation(cve) {
  const actions = [
    '1. Review the CVE details and assess the impact on your systems',
    '2. Check if any of your systems or applications are affected',
    '3. Apply vendor-provided patches or updates as soon as possible',
    '4. If patches are not available, implement compensating controls',
    '5. Monitor systems for signs of exploitation',
    '6. Review and update security policies as needed'
  ];
  
  return actions.join('\n');
}

/**
 * Get severity text based on CVSS score
 * @param {number} score - CVSS score
 * @returns {string} Severity description
 */
function getSeverityText(score) {
  if (score >= 9.0) return 'CRITICAL severity';
  if (score >= 8.0) return 'HIGH severity';
  if (score >= 7.0) return 'MEDIUM-HIGH severity';
  if (score >= 4.0) return 'MEDIUM severity';
  return 'LOW severity';
}

/**
 * Generate advisories for multiple CVEs
 * @param {Array} cves - Array of CVE objects
 * @returns {Array} Array of advisory objects
 */
function generateAdvisories(cves) {
  if (!Array.isArray(cves)) {
    throw new Error('CVEs must be an array');
  }
  
  return cves
    .filter(cve => {
      if (!cve || !cve.id) {
        console.warn('Skipping invalid CVE entry');
        return false;
      }
      return true;
    })
    .map(cve => {
      try {
        return generateAdvisory(cve);
      } catch (error) {
        console.error(`Error generating advisory for ${cve.id}: ${error.message}`);
        return null;
      }
    })
    .filter(advisory => advisory !== null);
}

module.exports = {
  generateAdvisory,
  generateAdvisories,
  generateSummary,
  generateImpact,
  generateRemediation
};
