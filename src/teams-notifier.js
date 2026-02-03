const fetch = require('node-fetch');

/**
 * Send security advisories to Microsoft Teams via webhook
 * Layout styled to match CIS Security Advisories
 */

/**
 * Format advisory as a Teams adaptive card
 * @param {Object} advisory - Advisory object
 * @returns {Object} Teams card payload
 */
function formatTeamsCard(advisory) {
  const severityColor = getSeverityColor(advisory.cvssScore);
  
  // Format references as a clean bulleted list of links
  // If there are more than 3, we show only the first 3 to keep the card tidy
  let referencesSection = [];
  if (advisory.references && advisory.references.length > 0) {
    const refLinks = advisory.references.slice(0, 4).map((ref, index) => {
      return `- [Reference Source ${index + 1}](${ref})`;
    }).join('\n');
    
    referencesSection = [
      {
        type: 'TextBlock',
        text: 'References',
        weight: 'Bolder',
        size: 'Medium',
        separator: true,
        spacing: 'Medium'
      },
      {
        type: 'TextBlock',
        text: refLinks,
        wrap: true,
        spacing: 'Small'
      }
    ];
  }

  const card = {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          type: 'AdaptiveCard',
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          version: '1.4',
          body: [
            // --- HEADER SECTION ---
            {
              type: 'Container',
              style: severityColor, // Colored background for header based on severity
              items: [
                {
                  type: 'TextBlock',
                  text: `Security Advisory: ${advisory.id}`,
                  size: 'ExtraLarge',
                  weight: 'Bolder',
                  wrap: true
                },
                {
                  type: 'TextBlock',
                  text: advisory.title.replace(`Security Advisory: ${advisory.id}`, 'Vulnerability Alert'), 
                  size: 'Medium',
                  wrap: true,
                  spacing: 'None',
                  isSubtle: true
                }
              ]
            },

            // --- METADATA BAR (Like CIS "Advisory Details") ---
            {
              type: 'Container',
              items: [
                {
                  type: 'FactSet',
                  facts: [
                    {
                      title: 'Published:',
                      value: new Date(advisory.publishedDate).toLocaleDateString()
                    },
                    {
                      title: 'Severity:',
                      value: `${advisory.severity.toUpperCase()} (${advisory.cvssScore})`
                    },
                    {
                      title: 'Vector:',
                      value: advisory.cvssVector || 'N/A'
                    }
                  ]
                }
              ],
              spacing: 'Small'
            },

            // --- SECTION: OVERVIEW ---
            {
              type: 'Container',
              separator: true,
              items: [
                {
                  type: 'TextBlock',
                  text: 'Overview',
                  weight: 'Bolder',
                  size: 'Medium',
                  color: 'Accent'
                },
                {
                  type: 'TextBlock',
                  // Use the raw description for a cleaner "CIS-style" overview
                  text: advisory.description,
                  wrap: true,
                  spacing: 'Small'
                }
              ]
            },

            // --- SECTION: RISK / IMPACT ---
            {
              type: 'Container',
              separator: true,
              items: [
                {
                  type: 'TextBlock',
                  text: 'Risk Assessment',
                  weight: 'Bolder',
                  size: 'Medium',
                  color: 'Accent'
                },
                {
                  type: 'TextBlock',
                  text: advisory.impact,
                  wrap: true,
                  spacing: 'Small'
                }
              ]
            },

            // --- SECTION: RECOMMENDATIONS ---
            {
              type: 'Container',
              separator: true,
              items: [
                {
                  type: 'TextBlock',
                  text: 'Recommendations',
                  weight: 'Bolder',
                  size: 'Medium',
                  color: 'Accent'
                },
                {
                  type: 'TextBlock',
                  text: advisory.remediation,
                  wrap: true,
                  spacing: 'Small'
                }
              ]
            },

            // --- SECTION: REFERENCES (Dynamic) ---
            ...referencesSection
          ],
          
          // --- FOOTER ACTIONS ---
          actions: [
            {
              type: 'Action.OpenUrl',
              title: '📄 Read Full Advisory on NVD',
              url: advisory.url
            }
          ]
        }
      }
    ]
  };
  
  return card;
}

/**
 * Get color based on CVSS severity
 * @param {number} cvssScore - CVSS score
 * @returns {string} Color name for Teams card
 */
function getSeverityColor(cvssScore) {
  if (cvssScore >= 9.0) return 'attention'; // Red for critical
  if (cvssScore >= 8.0) return 'warning';   // Orange/Yellow for high
  return 'default';
}

/**
 * Send advisory to Teams webhook
 * @param {string} webhookUrl - Teams webhook URL
 * @param {Object} advisory - Advisory object
 * @returns {Promise<boolean>} Success status
 */
async function sendToTeams(webhookUrl, advisory) {
  try {
    // Validate inputs
    if (!webhookUrl || typeof webhookUrl !== 'string') {
      throw new Error('Teams webhook URL is required and must be a string');
    }
    
    // Basic URL validation
    try {
      new URL(webhookUrl);
    } catch (e) {
      throw new Error('Invalid Teams webhook URL format');
    }
    
    if (!advisory || typeof advisory !== 'object') {
      throw new Error('Advisory must be an object');
    }
    
    if (!advisory.id) {
      throw new Error('Advisory must have an id');
    }
    
    const card = formatTeamsCard(advisory);
    
    // Add timeout to prevent hanging
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(card),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      const errorText = await response.text();
      // Log detailed error but throw sanitized message
      console.error(`Teams API error: Status ${response.status}, Details: ${errorText}`);
      throw new Error(`Teams webhook failed with status ${response.status}`);
    }
    
    console.log(`Successfully sent advisory for ${advisory.id} to Teams`);
    return true;
  } catch (error) {
    // Sanitize error messages to avoid leaking webhook URL or sensitive data
    const errorMessage = error.name === 'AbortError' 
      ? 'Teams webhook request timed out'
      : error.message;
    console.error(`Error sending to Teams: ${errorMessage}`);
    throw new Error(errorMessage);
  }
}

/**
 * Send multiple advisories to Teams
 * @param {string} webhookUrl - Teams webhook URL
 * @param {Array} advisories - Array of advisory objects
 * @returns {Promise<Object>} Results summary
 */
async function sendAdvisoriesToTeams(webhookUrl, advisories) {
  const results = {
    total: advisories.length,
    successful: 0,
    failed: 0,
    errors: []
  };
  
  for (const advisory of advisories) {
    try {
      await sendToTeams(webhookUrl, advisory);
      results.successful++;
      
      // Add a small delay between messages to avoid rate limiting
      if (advisories.length > 1) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } catch (error) {
      results.failed++;
      results.errors.push({
        cveId: advisory.id,
        error: error.message
      });
    }
  }
  
  console.log(`Sent ${results.successful}/${results.total} advisories to Teams`);
  
  return results;
}

module.exports = {
  sendToTeams,
  sendAdvisoriesToTeams,
  formatTeamsCard
};
