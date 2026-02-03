#!/usr/bin/env python3
"""
Vulnerability Advisory Filtering Script
For Navisite LLC and Accenture LLC SOC and Vulnerability Management Teams

This script filters security advisories based on keyword matching,
regex patterns, and severity thresholds.
"""

import json
import sys
import re
import yaml
from typing import List, Dict, Any, Set
from pathlib import Path


class AdvisoryFilter:
    """Filter security advisories based on configuration."""
    
    def __init__(self, config_path: str):
        """Initialize the filter with configuration."""
        self.config = self._load_config(config_path)
        self.keywords = self._extract_keywords()
        self.regex_patterns = self._compile_regex_patterns()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load filter configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            print(f"✓ Loaded configuration from {config_path}", file=sys.stderr)
            return config
        except Exception as e:
            print(f"✗ Error loading config: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _extract_keywords(self) -> Dict[str, Set[str]]:
        """Extract and normalize keywords from all categories."""
        keywords = {}
        categories = self.config.get('categories', {})
        
        for category_id, category_data in categories.items():
            category_name = category_data.get('name', category_id)
            category_keywords = set()
            
            for keyword in category_data.get('keywords', []):
                # Normalize: convert to lowercase and strip whitespace
                normalized = keyword.strip().lower()
                category_keywords.add(normalized)
            
            keywords[category_id] = category_keywords
            print(f"✓ Loaded {len(category_keywords)} keywords for category: {category_name}", 
                  file=sys.stderr)
        
        return keywords
    
    def _compile_regex_patterns(self) -> List[Dict[str, Any]]:
        """Compile regex patterns from configuration."""
        patterns = []
        regex_config = self.config.get('regex_patterns', {})
        
        if not regex_config.get('enabled', True):
            return patterns
        
        for pattern_config in regex_config.get('patterns', []):
            try:
                compiled = re.compile(pattern_config['pattern'], re.IGNORECASE)
                patterns.append({
                    'pattern': compiled,
                    'description': pattern_config.get('description', ''),
                    'original': pattern_config['pattern']
                })
            except re.error as e:
                print(f"✗ Invalid regex pattern: {pattern_config['pattern']} - {e}", 
                      file=sys.stderr)
        
        print(f"✓ Compiled {len(patterns)} regex patterns", file=sys.stderr)
        return patterns
    
    def _check_severity(self, advisory: Dict[str, Any]) -> bool:
        """Check if advisory meets severity threshold."""
        severity_config = self.config.get('severity', {})
        
        if not severity_config.get('enabled', True):
            return True
        
        min_cvss = severity_config.get('min_cvss', 0.0)
        allowed_levels = severity_config.get('levels', ['critical', 'high', 'medium', 'low'])
        
        # Check CVSS score
        cvss_score = advisory.get('cvssScore', 0.0)
        if cvss_score < min_cvss:
            return False
        
        # Check severity level
        severity = advisory.get('severity', '').lower()
        if severity and severity not in [level.lower() for level in allowed_levels]:
            return False
        
        return True
    
    def _match_keywords(self, text: str, category_id: str) -> List[str]:
        """Match keywords using flexible matching for special characters."""
        matched = []
        category_keywords = self.keywords.get(category_id, set())
        text_lower = text.lower()
        
        for keyword in category_keywords:
            # Use word boundary matching for alphanumeric keywords
            # For keywords with special chars (dots, hyphens, spaces), use simple substring matching
            if re.match(r'^[\w]+$', keyword):
                # Pure alphanumeric - use word boundaries
                pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(pattern, text_lower, re.IGNORECASE):
                    matched.append(keyword)
            else:
                # Contains special characters - use substring matching
                if keyword in text_lower:
                    matched.append(keyword)
        
        return matched
    
    def _match_regex_patterns(self, text: str) -> List[Dict[str, str]]:
        """Match regex patterns against text."""
        matched = []
        
        for pattern_info in self.regex_patterns:
            if pattern_info['pattern'].search(text):
                matched.append({
                    'description': pattern_info['description'],
                    'pattern': pattern_info['original']
                })
        
        return matched
    
    def _calculate_relevance_score(self, matches: Dict[str, Any], advisory: Dict[str, Any]) -> int:
        """Calculate relevance score for ranking."""
        ranking_config = self.config.get('ranking', {})
        
        if not ranking_config.get('enabled', True):
            return 1
        
        weights = ranking_config.get('weights', {})
        score = 0
        
        # Add points for keyword matches
        total_keyword_matches = sum(len(keywords) for keywords in matches['matched_keywords'].values())
        score += total_keyword_matches * weights.get('exact_match', 10)
        
        # Add points for category matches
        score += len(matches['matched_categories']) * weights.get('category_match', 5)
        
        # Add points for regex matches
        score += len(matches['matched_patterns']) * weights.get('regex_match', 7)
        
        # Add points based on severity
        severity = advisory.get('severity', '').lower()
        if severity == 'critical':
            score += weights.get('severity_critical', 15)
        elif severity == 'high':
            score += weights.get('severity_high', 10)
        elif severity == 'medium':
            score += weights.get('severity_medium', 5)
        
        return score
    
    def filter_advisory(self, advisory: Dict[str, Any]) -> Dict[str, Any]:
        """Filter a single advisory and return match details."""
        # Check severity first
        if not self._check_severity(advisory):
            return None
        
        # Combine searchable text from advisory
        searchable_text = ' '.join([
            advisory.get('id', ''),
            advisory.get('description', ''),
            advisory.get('summary', ''),
            advisory.get('title', ''),
            ' '.join(advisory.get('references', []))
        ])
        
        # Match keywords across all categories
        matched_keywords = {}
        matched_categories = []
        
        for category_id, category_data in self.config.get('categories', {}).items():
            category_name = category_data.get('name', category_id)
            keywords = self._match_keywords(searchable_text, category_id)
            
            if keywords:
                matched_keywords[category_name] = keywords
                matched_categories.append(category_name)
        
        # Match regex patterns
        matched_patterns = self._match_regex_patterns(searchable_text)
        
        # If no matches found, skip this advisory
        if not matched_keywords and not matched_patterns:
            return None
        
        # Calculate relevance score
        matches = {
            'matched_keywords': matched_keywords,
            'matched_categories': matched_categories,
            'matched_patterns': matched_patterns
        }
        
        relevance_score = self._calculate_relevance_score(matches, advisory)
        
        return {
            'advisory': advisory,
            'matches': matches,
            'relevance_score': relevance_score
        }
    
    def filter_advisories(self, advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter multiple advisories and return ranked results."""
        filtered = []
        
        print(f"Processing {len(advisories)} advisories...", file=sys.stderr)
        
        for advisory in advisories:
            result = self.filter_advisory(advisory)
            if result:
                filtered.append(result)
        
        # Sort by relevance score (highest first)
        filtered.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        # Limit results based on configuration
        max_results = self.config.get('ranking', {}).get('max_results', 20)
        filtered = filtered[:max_results]
        
        print(f"✓ Filtered to {len(filtered)} relevant advisories", file=sys.stderr)
        
        return filtered


def main():
    """Main entry point for the script."""
    if len(sys.argv) < 3:
        print("Usage: filter_advisories.py <config_file> <advisories_file>", file=sys.stderr)
        sys.exit(1)
    
    config_file = sys.argv[1]
    advisories_file = sys.argv[2]
    
    # Load advisories
    try:
        with open(advisories_file, 'r') as f:
            advisories = json.load(f)
        
        # Support both array and single advisory
        if not isinstance(advisories, list):
            advisories = [advisories]
        
        print(f"✓ Loaded {len(advisories)} advisories from {advisories_file}", file=sys.stderr)
    except Exception as e:
        print(f"✗ Error loading advisories: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Create filter and process advisories
    filter_engine = AdvisoryFilter(config_file)
    filtered_results = filter_engine.filter_advisories(advisories)
    
    # Output results as JSON
    filter_efficiency = (len(filtered_results) / len(advisories) * 100) if len(advisories) > 0 else 0.0
    output = {
        'total_advisories': len(advisories),
        'filtered_advisories': len(filtered_results),
        'results': filtered_results,
        'statistics': {
            'filter_efficiency': f"{filter_efficiency:.1f}%",
            'categories_used': len(filter_engine.keywords),
            'regex_patterns_used': len(filter_engine.regex_patterns)
        }
    }
    
    # Print to stdout for consumption by GitHub Actions
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
