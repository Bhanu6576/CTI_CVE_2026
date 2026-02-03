#!/usr/bin/env python3
"""
Notification Generator for Filtered Vulnerability Advisories
For Navisite LLC and Accenture LLC SOC and Vulnerability Management Teams

This script formats filtered advisories into readable markdown notifications
for Teams and Slack.
"""

import json
import sys
from typing import List, Dict, Any
from datetime import datetime


class NotificationGenerator:
    """Generate formatted notifications from filtered advisories."""
    
    # Severity emojis
    SEVERITY_EMOJIS = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'unknown': '⚪'
    }
    
    # Description truncation settings
    MAX_DESCRIPTION_LENGTH = 300
    TRUNCATION_SUFFIX = '...'
    TEAMS_MAX_DESCRIPTION_LENGTH = 150
    SLACK_MAX_DESCRIPTION_LENGTH = 200
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        severity_lower = severity.lower() if severity else 'unknown'
        return self.SEVERITY_EMOJIS.get(severity_lower, self.SEVERITY_EMOJIS['unknown'])
    
    def _format_advisory_summary(self, result: Dict[str, Any], rank: int) -> str:
        """Format a single advisory as a markdown section."""
        advisory = result['advisory']
        matches = result['matches']
        relevance_score = result['relevance_score']
        
        cve_id = advisory.get('id', 'N/A')
        severity = advisory.get('severity', 'UNKNOWN')
        cvss_score = advisory.get('cvssScore', 0.0)
        description = advisory.get('description', 'No description available')
        url = advisory.get('url', '')
        published = advisory.get('publishedDate', '')
        
        # Format published date
        if published:
            try:
                dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
                published_str = dt.strftime('%Y-%m-%d')
            except (ValueError, AttributeError):
                published_str = published.split('T')[0] if 'T' in published else published
        else:
            published_str = 'N/A'
        
        # Get emoji for severity
        emoji = self._get_severity_emoji(severity)
        
        # Build the markdown
        md = []
        md.append(f"### {rank}. {emoji} {cve_id} - {severity.upper()} ({cvss_score})")
        md.append("")
        md.append(f"**Published:** {published_str} | **Relevance Score:** {relevance_score}")
        md.append("")
        
        # Description (truncate if too long)
        if len(description) > self.MAX_DESCRIPTION_LENGTH:
            description = description[:self.MAX_DESCRIPTION_LENGTH - len(self.TRUNCATION_SUFFIX)] + self.TRUNCATION_SUFFIX
        md.append(f"**Description:** {description}")
        md.append("")
        
        # Matched categories
        if matches['matched_categories']:
            categories_str = ', '.join(matches['matched_categories'])
            md.append(f"**Matched Categories:** {categories_str}")
            md.append("")
        
        # Matched keywords (show first 10)
        all_keywords = []
        for category, keywords in matches['matched_keywords'].items():
            all_keywords.extend(keywords)
        
        if all_keywords:
            keywords_display = all_keywords[:10]
            keywords_str = ', '.join([f"`{kw}`" for kw in keywords_display])
            if len(all_keywords) > 10:
                keywords_str += f" ... (+{len(all_keywords) - 10} more)"
            md.append(f"**Matched Keywords:** {keywords_str}")
            md.append("")
        
        # Matched patterns
        if matches['matched_patterns']:
            patterns_str = ', '.join([p['description'] for p in matches['matched_patterns']])
            md.append(f"**Matched Patterns:** {patterns_str}")
            md.append("")
        
        # Link
        if url:
            md.append(f"**Link:** [{cve_id}]({url})")
        
        md.append("")
        md.append("---")
        md.append("")
        
        return '\n'.join(md)
    
    def generate_markdown(self, filtered_data: Dict[str, Any]) -> str:
        """Generate complete markdown notification."""
        results = filtered_data.get('results', [])
        total = filtered_data.get('total_advisories', 0)
        filtered = filtered_data.get('filtered_advisories', 0)
        stats = filtered_data.get('statistics', {})
        
        md = []
        
        # Header
        md.append("# 🔒 Security Advisory Notification")
        md.append("")
        md.append("**Navisite LLC & Accenture LLC Vulnerability Management**")
        md.append("")
        md.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append("")
        
        # Statistics
        md.append("## 📊 Filter Statistics")
        md.append("")
        md.append(f"- **Total Advisories Scanned:** {total}")
        md.append(f"- **Relevant Advisories Found:** {filtered}")
        md.append(f"- **Filter Efficiency:** {stats.get('filter_efficiency', 'N/A')}")
        md.append(f"- **Categories Used:** {stats.get('categories_used', 0)}")
        md.append(f"- **Regex Patterns Used:** {stats.get('regex_patterns_used', 0)}")
        md.append("")
        
        if not results:
            md.append("## ✅ No Relevant Vulnerabilities")
            md.append("")
            md.append("No vulnerabilities matching your technology stack were found in this scan.")
            md.append("")
            return '\n'.join(md)
        
        # Severity breakdown
        severity_counts = {}
        for result in results:
            severity = result['advisory'].get('severity', 'UNKNOWN').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        md.append("## 🎯 Severity Breakdown")
        md.append("")
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in severity_counts:
                emoji = self._get_severity_emoji(severity)
                count = severity_counts[severity]
                md.append(f"- {emoji} **{severity.upper()}:** {count}")
        md.append("")
        
        # Advisories
        md.append("## 🚨 Relevant Security Advisories")
        md.append("")
        
        for idx, result in enumerate(results, 1):
            md.append(self._format_advisory_summary(result, idx))
        
        # Footer
        md.append("---")
        md.append("")
        md.append("*This notification was automatically generated by the Vulnerability Advisory Automation System.*")
        md.append("")
        
        return '\n'.join(md)
    
    def generate_json(self, filtered_data: Dict[str, Any]) -> str:
        """Generate JSON output for programmatic consumption."""
        return json.dumps(filtered_data, indent=2)
    
    def generate_teams_payload(self, filtered_data: Dict[str, Any]) -> str:
        """Generate Microsoft Teams webhook payload (Adaptive Card)."""
        results = filtered_data.get('results', [])
        total = filtered_data.get('total_advisories', 0)
        filtered = filtered_data.get('filtered_advisories', 0)
        
        # Build facts for the card
        facts = [
            {
                "title": "Total Scanned:",
                "value": str(total)
            },
            {
                "title": "Relevant Found:",
                "value": str(filtered)
            },
            {
                "title": "Generated:",
                "value": datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
            }
        ]
        
        # Build advisory sections (limit to first 5 for Teams)
        advisory_sections = []
        for idx, result in enumerate(results[:5], 1):
            advisory = result['advisory']
            matches = result['matches']
            
            cve_id = advisory.get('id', 'N/A')
            severity = advisory.get('severity', 'UNKNOWN')
            cvss_score = advisory.get('cvssScore', 0.0)
            description = advisory.get('description', '')
            
            # Truncate description
            if len(description) > self.TEAMS_MAX_DESCRIPTION_LENGTH:
                description = description[:self.TEAMS_MAX_DESCRIPTION_LENGTH - len(self.TRUNCATION_SUFFIX)] + self.TRUNCATION_SUFFIX
            
            # Get matched categories
            categories_str = ', '.join(matches['matched_categories'][:3])
            if len(matches['matched_categories']) > 3:
                categories_str += f" (+{len(matches['matched_categories']) - 3} more)"
            
            advisory_sections.append({
                "type": "Container",
                "separator": True,
                "items": [
                    {
                        "type": "TextBlock",
                        "text": f"{self._get_severity_emoji(severity)} {cve_id}",
                        "weight": "Bolder",
                        "size": "Medium"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "Severity:",
                                "value": f"{severity.upper()} ({cvss_score})"
                            },
                            {
                                "title": "Categories:",
                                "value": categories_str
                            }
                        ]
                    },
                    {
                        "type": "TextBlock",
                        "text": description,
                        "wrap": True,
                        "spacing": "Small"
                    }
                ]
            })
        
        if len(results) > 5:
            advisory_sections.append({
                "type": "TextBlock",
                "text": f"... and {len(results) - 5} more advisories",
                "isSubtle": True,
                "spacing": "Medium"
            })
        
        # Build the card
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "Container",
                                "style": "emphasis",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "🔒 Security Advisory Notification",
                                        "size": "ExtraLarge",
                                        "weight": "Bolder",
                                        "wrap": True
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": "Navisite LLC & Accenture LLC",
                                        "isSubtle": True,
                                        "spacing": "None"
                                    }
                                ]
                            },
                            {
                                "type": "Container",
                                "items": [
                                    {
                                        "type": "FactSet",
                                        "facts": facts
                                    }
                                ]
                            },
                            *advisory_sections
                        ]
                    }
                }
            ]
        }
        
        return json.dumps(card, indent=2)
    
    def generate_slack_payload(self, filtered_data: Dict[str, Any]) -> str:
        """Generate Slack webhook payload."""
        results = filtered_data.get('results', [])
        total = filtered_data.get('total_advisories', 0)
        filtered = filtered_data.get('filtered_advisories', 0)
        
        # Build blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔒 Security Advisory Notification"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Navisite LLC & Accenture LLC Vulnerability Management*"
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Scanned:*\n{total}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Relevant Found:*\n{filtered}"
                    }
                ]
            }
        ]
        
        # Add advisories (limit to 5 for Slack)
        for idx, result in enumerate(results[:5], 1):
            advisory = result['advisory']
            matches = result['matches']
            
            cve_id = advisory.get('id', 'N/A')
            severity = advisory.get('severity', 'UNKNOWN')
            cvss_score = advisory.get('cvssScore', 0.0)
            url = advisory.get('url', '')
            
            emoji = self._get_severity_emoji(severity)
            categories_str = ', '.join(matches['matched_categories'][:3])
            
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{emoji} {cve_id}*\n*Severity:* {severity.upper()} ({cvss_score})\n*Categories:* {categories_str}\n<{url}|View Details>"
                }
            })
        
        if len(results) > 5:
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"_... and {len(results) - 5} more advisories_"
                    }
                ]
            })
        
        payload = {
            "blocks": blocks
        }
        
        return json.dumps(payload, indent=2)


def main():
    """Main entry point for the script."""
    if len(sys.argv) < 3:
        print("Usage: generate_notification.py <filtered_results_file> <output_format>", file=sys.stderr)
        print("Output formats: markdown, json, teams, slack", file=sys.stderr)
        sys.exit(1)
    
    results_file = sys.argv[1]
    output_format = sys.argv[2].lower()
    
    # Load filtered results
    try:
        with open(results_file, 'r') as f:
            filtered_data = json.load(f)
        print(f"✓ Loaded filtered results from {results_file}", file=sys.stderr)
    except Exception as e:
        print(f"✗ Error loading results: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Generate notification
    generator = NotificationGenerator()
    
    if output_format == 'markdown':
        output = generator.generate_markdown(filtered_data)
    elif output_format == 'json':
        output = generator.generate_json(filtered_data)
    elif output_format == 'teams':
        output = generator.generate_teams_payload(filtered_data)
    elif output_format == 'slack':
        output = generator.generate_slack_payload(filtered_data)
    else:
        print(f"✗ Unknown output format: {output_format}", file=sys.stderr)
        print("Supported formats: markdown, json, teams, slack", file=sys.stderr)
        sys.exit(1)
    
    # Print to stdout
    print(output)


if __name__ == '__main__':
    main()
