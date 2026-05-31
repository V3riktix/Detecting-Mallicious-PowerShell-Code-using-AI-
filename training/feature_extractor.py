"""
Feature extraction for PowerShell malicious script detection
Extracts textual, token, and AST-based features
"""

import re
from collections import Counter
import numpy as np


class PowerShellFeatureExtractor:
    """Extract features from PowerShell scripts"""
    
    # Common malicious PowerShell tokens
    MALICIOUS_KEYWORDS = {
        'invoke-expression', 'iex', 'invoke-command', 'icm',
        'downloadstring', 'webrequest', 'webclient', 'invoke-webrequest',
        'cmd', 'command', 'powershell', 'exec', 'execute',
        'registry', 'reg', 'add', 'delete', 'replace',
        'wmi', 'win32', 'activex', 'process', 'kill',
        'rundll32', 'regsvcs', 'regasm', 'installutil',
        'mshta', 'winrm', 'wmic', 'sc.exe', 'net.exe',
        'firewall', 'defender', 'antivirus', 'security'
    }
    
    # Suspicious functions
    SUSPICIOUS_FUNCTIONS = {
        'New-Object', 'Add-Type', 'Out-String', 'ConvertTo-SecureString',
        'System.Net', 'System.IO', 'System.Diagnostics', 'System.Reflection'
    }
    
    @staticmethod
    def extract_textual_features(script_content):
        """Extract textual features from script"""
        features = {}
        
        # Basic statistics
        features['script_length'] = len(script_content)
        features['line_count'] = len(script_content.split('\n'))
        features['word_count'] = len(script_content.split())
        
        # Character statistics
        features['uppercase_ratio'] = sum(1 for c in script_content if c.isupper()) / (len(script_content) + 1)
        features['digit_ratio'] = sum(1 for c in script_content if c.isdigit()) / (len(script_content) + 1)
        features['special_char_ratio'] = sum(1 for c in script_content if not c.isalnum() and not c.isspace()) / (len(script_content) + 1)
        
        # Entropy (measure of randomness)
        char_counts = Counter(script_content)
        entropy = 0
        for count in char_counts.values():
            p = count / len(script_content)
            entropy -= p * np.log2(p) if p > 0 else 0
        features['entropy'] = entropy
        
        return features
    
    @staticmethod
    def extract_token_features(script_content):
        """Extract token-based features"""
        features = {}
        
        # Normalize to lowercase for token matching
        script_lower = script_content.lower()
        
        # Count malicious keywords
        malicious_count = 0
        for keyword in PowerShellFeatureExtractor.MALICIOUS_KEYWORDS:
            malicious_count += len(re.findall(r'\b' + re.escape(keyword) + r'\b', script_lower))
        features['malicious_keyword_count'] = malicious_count
        features['malicious_keyword_ratio'] = malicious_count / (len(script_content.split()) + 1)
        
        # Count suspicious functions
        suspicious_count = 0
        for func in PowerShellFeatureExtractor.SUSPICIOUS_FUNCTIONS:
            suspicious_count += script_lower.count(func.lower())
        features['suspicious_function_count'] = suspicious_count
        
        # Encoding/obfuscation indicators
        features['has_base64'] = 1 if re.search(r'FromBase64String|ConvertFrom-SecureString', script_content, re.IGNORECASE) else 0
        features['has_hex'] = 1 if re.search(r'0x[0-9a-fA-F]+', script_content) else 0
        features['has_unicode_escape'] = 1 if re.search(r'\\u[0-9a-fA-F]{4}', script_content) else 0
        
        # Variable assignments
        features['variable_count'] = len(re.findall(r'\$\w+', script_content))
        
        # Comment density
        comment_count = len(re.findall(r'#[^\n]*', script_content))
        features['comment_ratio'] = comment_count / (len(script_content.split('\n')) + 1)
        
        # String literals count
        features['string_literal_count'] = len(re.findall(r'["\'].*?["\']', script_content, re.DOTALL))
        
        # Pipeline operators
        features['pipeline_count'] = script_content.count('|')
        
        # Parentheses (function calls)
        features['parenthesis_count'] = script_content.count('(') + script_content.count(')')
        
        return features
    
    @staticmethod
    def extract_syntax_features(script_content):
        """Extract syntax/structure features"""
        features = {}
        
        # Control flow statements
        features['if_count'] = len(re.findall(r'\bif\b', script_content, re.IGNORECASE))
        features['for_count'] = len(re.findall(r'\bfor\b', script_content, re.IGNORECASE))
        features['while_count'] = len(re.findall(r'\bwhile\b', script_content, re.IGNORECASE))
        features['foreach_count'] = len(re.findall(r'\bforeach\b', script_content, re.IGNORECASE))
        features['try_catch_count'] = len(re.findall(r'\btry\b', script_content, re.IGNORECASE))
        
        features['control_flow_total'] = (features['if_count'] + features['for_count'] + 
                                         features['while_count'] + features['foreach_count'] + 
                                         features['try_catch_count'])
        
        # Function definitions
        features['function_def_count'] = len(re.findall(r'function\s+\w+', script_content, re.IGNORECASE))
        
        # Brackets and braces
        features['bracket_count'] = script_content.count('[') + script_content.count(']')
        features['brace_count'] = script_content.count('{') + script_content.count('}')
        
        # Dots and colons (namespace/method access)
        features['dot_count'] = script_content.count('.')
        features['colon_count'] = script_content.count(':')
        
        return features
    
    @staticmethod
    def extract_all_features(script_content):
        """Extract all features from a PowerShell script"""
        features = {}
        
        # Extract different feature types
        textual_feat = PowerShellFeatureExtractor.extract_textual_features(script_content)
        token_feat = PowerShellFeatureExtractor.extract_token_features(script_content)
        syntax_feat = PowerShellFeatureExtractor.extract_syntax_features(script_content)
        
        # Combine all features
        features.update(textual_feat)
        features.update(token_feat)
        features.update(syntax_feat)
        
        return features
    
    @staticmethod
    def get_feature_names():
        """Get list of all feature names in order"""
        dummy_features = PowerShellFeatureExtractor.extract_all_features("dummy")
        return sorted(dummy_features.keys())
    
    @staticmethod
    def features_to_array(features_dict):
        """Convert features dict to ordered numpy array"""
        feature_names = PowerShellFeatureExtractor.get_feature_names()
        return np.array([features_dict.get(fname, 0) for fname in feature_names])
