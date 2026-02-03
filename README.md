# Vulnerability Advisory Automation 🔒

Automated system for discovering, tracking, and notifying about high-severity CVEs using GitHub Actions, NVD API, and Microsoft Teams.

## 🚀 Workflow Overview

The automation includes:

- **GitHub Actions Workflow** - Runs automatically every 6 hours
- **CVE Search Engine** - Searches NVD API for CVEs with CVSS ≥ 8.0
- **🆕 Intelligent Filtering System** - Filters CVEs by technology keywords and relevance
- **Deduplication System** - Maintains last 20 CVEs in memory to prevent duplicates
- **Security Advisory Generator** - Creates formatted security advisories
- **Teams Integration** - Sends notifications via Microsoft Teams webhook
- **Slack Integration** - Sends notifications via Slack webhook
- **State Management** - Stores processed CVEs for tracking

## 🆕 Advanced Filtering (NEW!)

The new filtering system dramatically reduces notification noise by only alerting about advisories matching your technology stack.

### Features:
- **30 Technology Categories** - Cloud, OS, Databases, Security Products, etc.
- **500+ Keywords** - Comprehensive coverage of common technologies
- **Regex Patterns** - Advanced matching for complex scenarios
- **Relevance Scoring** - Ranks advisories by match quality
- **Severity Filtering** - Focus on critical/high/medium severity issues
- **Multi-Format Notifications** - Markdown, Teams, and Slack formats

### Quick Start with Filtering:

Use the new enhanced workflow:
```yaml
.github/workflows/cve-automation-with-filter.yml
```

This workflow:
1. Fetches CVEs from NVD API
2. Filters by keywords matching your tech stack
3. Ranks by relevance score
4. Sends only relevant advisories to Teams/Slack
5. Generates comprehensive reports

### Configuration:

Edit `.github/workflows/filter-config.yml` to customize:
- Add/remove technology categories
- Adjust keyword lists
- Configure severity thresholds
- Modify regex patterns
- Set maximum results limit

## 📁 Key Files

### `.github/workflows/cve-automation.yml`
Main GitHub Actions workflow that:
- Triggers every 6 hours (at 0, 6, 12, 18 UTC)
- Calls the CVE search service
- Generates security advisories
- Posts to Teams webhook
- Manages deduplication state

### `src/cve-search.js`
CVE search module that:
- Queries NVD API for CVEs with CVSS ≥ 8.0
- Returns formatted CVE details
- Handles API errors gracefully
- Supports optional API key for better rate limits

### `src/deduplication.js`
Deduplication engine that:
- Maintains a window of last 20 processed CVEs
- Checks against duplicates
- Updates the tracking list
- Persists state across workflow runs

### `src/teams-notifier.js`
Teams integration that:
- Formats security advisories as Teams adaptive cards
- Posts via webhook URL
- Includes CVE details, scores, and remediation info
- Handles multiple advisories with rate limiting

### `src/advisory-generator.js`
Creates comprehensive security advisories with:
- Summary and impact assessment
- Remediation steps
- Reference links
- Severity categorization

### 🆕 `.github/workflows/cve-automation-with-filter.yml`
Enhanced workflow with intelligent filtering:
- Fetches CVEs from NVD API
- Filters by technology keywords
- Ranks by relevance score
- Sends to Teams and Slack
- Generates workflow summaries
- Uploads artifacts for review

### 🆕 `.github/workflows/filter-config.yml`
Filter configuration with:
- 30 technology categories
- 500+ keywords for common technologies
- Advanced regex patterns
- Severity threshold settings
- Relevance scoring weights

### 🆕 `scripts/filter_advisories.py`
Python filtering engine that:
- Loads filter configuration from YAML
- Performs word boundary keyword matching
- Applies regex pattern matching
- Filters by severity (critical/high/medium)
- Calculates relevance scores
- Outputs JSON with match details

### 🆕 `scripts/generate_notification.py`
Multi-format notification generator:
- Markdown with severity emojis (🔴🟠🟡🟢)
- Microsoft Teams Adaptive Cards
- Slack Block Kit format
- Displays matched keywords and categories
- Shows top 20 most relevant advisories


### `.github/workflows/state.json`
Maintains state across workflow runs:
- List of processed CVE IDs
- Last update timestamp

## ⚙️ Setup Instructions

### 1. Add Teams Webhook URL as Secret

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Create a new secret: `TEAMS_WEBHOOK_URL`
3. Paste your Microsoft Teams channel webhook URL

**How to get a Teams webhook URL:**
- In Microsoft Teams, go to your channel
- Click the three dots (⋯) → **Connectors** → **Incoming Webhook**
- Configure and copy the webhook URL

### 2. 🆕 Add Slack Webhook URL as Secret (Optional)

1. Go to your repository **Settings** → **Secrets and variables** → **Actions**
2. Create a new secret: `SLACK_WEBHOOK_URL`
3. Paste your Slack channel webhook URL

**How to get a Slack webhook URL:**
- Go to [Slack API](https://api.slack.com/messaging/webhooks)
- Create a new Incoming Webhook
- Select your channel and copy the webhook URL

### 3. Configure NVD API (Optional but Recommended)

1. Get a free API key from [NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key)
2. Add as secret: `NVD_API_KEY`

**Benefits of using an API key:**
- Higher rate limits (50 requests per 30 seconds vs 5 without key)
- More reliable service
- Priority processing

### 4. 🆕 Choose Your Workflow

**Option A: With Filtering (Recommended for Navisite/Accenture)**
Use `.github/workflows/cve-automation-with-filter.yml` for intelligent filtering

**Option B: Original Workflow**
Use `.github/workflows/cve-automation.yml` for all high-severity CVEs

### 5. Enable GitHub Actions

1. Ensure Actions are enabled in your repository settings
2. The workflow will automatically run every 6 hours
3. You can also trigger it manually from the Actions tab

### 6. 🆕 Customize Filtering (Optional)

**Adjust technology keywords:**
- Edit `.github/workflows/filter-config.yml`
- Add/remove categories and keywords
- Modify regex patterns

**Adjust severity threshold:**
- Edit the `severity` section in filter-config.yml
- Set minimum CVSS score (default: 4.0)
- Choose which severity levels to include

**Adjust CVSS threshold:**
- Edit the workflow file to change the default threshold
- Or use manual trigger with custom threshold

**Modify Teams card format:**
- Edit `src/teams-notifier.js` to customize the card layout

**Change schedule:**
- Modify the cron expression in the workflow file
- Current: `0 0,6,12,18 * * *` (every 6 hours)

## 🔧 Manual Execution

You can manually trigger the workflow:

1. Go to the **Actions** tab in your repository
2. Select **CVE Automation Workflow** or **CVE Automation with Filtering**
3. Click **Run workflow**
4. Optionally set a custom CVSS threshold

## 📊 How It Works

### Original Workflow:
1. **Scheduled Trigger**: Workflow runs every 6 hours
2. **Search CVEs**: Queries NVD API for recent high-severity vulnerabilities
3. **Deduplication**: Filters out CVEs that were already processed
4. **Generate Advisories**: Creates detailed security advisories
5. **Notify Teams**: Sends formatted cards to Microsoft Teams channel
6. **Update State**: Saves processed CVE IDs to prevent future duplicates
7. **Commit Changes**: Updates state file and advisory records

### 🆕 Enhanced Workflow with Filtering:
1. **Scheduled Trigger**: Workflow runs every 6 hours
2. **Search CVEs**: Queries NVD API for recent high-severity vulnerabilities
3. **🆕 Intelligent Filtering**: Matches CVEs against 500+ technology keywords
4. **🆕 Relevance Ranking**: Scores and ranks CVEs by match quality
5. **Deduplication**: Filters out CVEs that were already processed
6. **Generate Advisories**: Creates detailed security advisories
7. **🆕 Multi-Channel Notify**: Sends to Teams and/or Slack
8. **🆕 Summary Reports**: Generates detailed workflow summaries
9. **Update State**: Saves processed CVE IDs to prevent future duplicates
10. **Commit Changes**: Updates state file and advisory records

## 🎯 Filtering Benefits

The new filtering system provides:

- **Reduced Noise**: Only see CVEs relevant to your technology stack
- **Time Savings**: No need to manually review irrelevant advisories
- **Better Prioritization**: Relevance scores help focus on the most important issues
- **Comprehensive Coverage**: 30 categories cover cloud, OS, databases, security tools, etc.
- **Customizable**: Easy to add/remove keywords for your specific environment
- **Multi-Format**: Choose between Markdown, Teams, or Slack notifications

**Example**: Instead of receiving 50+ CVE notifications daily, you might receive only 5-10 that are actually relevant to your infrastructure (Apache Tomcat, Kubernetes, Azure AD, etc.).

## 📈 Monitoring

- Check the **Actions** tab for workflow execution logs
- Review generated advisories in `data/advisories/`
- Monitor Teams/Slack channels for notifications
- Check state file for tracked CVEs
- 🆕 Review workflow summaries for filter statistics
- 🆕 Download artifacts for detailed analysis

## 🛠️ Troubleshooting

**No CVEs appearing:**
- Verify the CVSS threshold is appropriate (default: 8.0)
- Check if NVD API is accessible
- Review workflow logs for API errors

**🆕 Too few/many filtered results:**
- Adjust keywords in `.github/workflows/filter-config.yml`
- Modify severity threshold settings
- Check regex patterns for accuracy
- Review relevance scoring weights

**Teams notifications not working:**
- Verify `TEAMS_WEBHOOK_URL` secret is configured correctly
- Test the webhook URL manually
- Check Teams channel permissions

**🆕 Slack notifications not working:**
- Verify `SLACK_WEBHOOK_URL` secret is configured correctly
- Test the webhook URL manually
- Check Slack channel permissions

**Duplicate notifications:**
- Verify state file is being committed properly
- Check deduplication logs in workflow output

**🆕 Python script errors:**
- Ensure Python 3.11+ is available
- Check that PyYAML is installed
- Review error messages in workflow logs
- Validate YAML syntax in filter-config.yml

## 📝 License

This project is open source and available for use.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
