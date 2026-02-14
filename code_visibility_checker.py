"""
Code Visibility Checker & Auto-Formatter
Detects and fixes hidden/obscured code patterns
"""

import re
import ast
from typing import Dict, List, Tuple

class CodeVisibilityChecker:
    """
    Detects code obfuscation techniques and hidden malicious patterns
    Used for attachment scanning and downloaded code analysis
    """
    
    def __init__(self):
        self.suspicious_patterns = []
        self.reformatted_code = None
        
    def analyze_code(self, code: str, language: str = 'python') -> Dict:
        """
        Comprehensive code analysis for visibility issues and malicious patterns
        """
        analysis = {
            'is_safe': True,
            'threat_score': 0,
            'issues': [],
            'reformatted_code': code,
            'recommendations': []
        }
        
        # 1. Check for obfuscation
        obfuscation = self._detect_obfuscation(code)
        if obfuscation['is_obfuscated']:
            analysis['is_safe'] = False
            analysis['threat_score'] += 40
            analysis['issues'].extend(obfuscation['patterns'])
        
        # 2. Check for hidden characters
        hidden = self._detect_hidden_characters(code)
        if hidden['has_hidden']:
            analysis['is_safe'] = False
            analysis['threat_score'] += 30
            analysis['issues'].extend(hidden['issues'])
            analysis['reformatted_code'] = hidden['cleaned_code']
        
        # 3. Check for malicious patterns
        malicious = self._detect_malicious_patterns(code, language)
        if malicious['is_suspicious']:
            analysis['is_safe'] = False
            analysis['threat_score'] += malicious['score']
            analysis['issues'].extend(malicious['patterns'])
        
        # 4. Check for code compression/minification
        if self._is_minified(code):
            analysis['threat_score'] += 20
            analysis['issues'].append({
                'type': 'minified_code',
                'severity': 'medium',
                'description': 'Code appears to be minified/compressed'
            })
            analysis['reformatted_code'] = self._reformat_code(code, language)
        
        # 5. Check for encoding tricks
        encoding = self._detect_encoding_tricks(code)
        if encoding['has_tricks']:
            analysis['threat_score'] += 35
            analysis['issues'].extend(encoding['tricks'])
        
        # 6. Visual analysis (top-right overflow, long lines)
        visual = self._analyze_visual_layout(code)
        if visual['has_issues']:
            analysis['issues'].extend(visual['issues'])
            analysis['reformatted_code'] = visual['reformatted']
        
        analysis['threat_score'] = min(100, analysis['threat_score'])
        
        # Generate recommendations
        if analysis['threat_score'] > 0:
            analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _detect_obfuscation(self, code: str) -> Dict:
        """Detect code obfuscation techniques"""
        patterns = []
        
        # Base64 encoding
        if re.search(r'base64\.(b64decode|decodebytes)', code):
            patterns.append({
                'type': 'base64_decode',
                'severity': 'high',
                'description': 'Uses Base64 decoding (common in malware)'
            })
        
        # Exec/eval with encoded strings
        if re.search(r'(exec|eval)\s*\([\'"].*?[\'\"]\)', code):
            patterns.append({
                'type': 'dynamic_execution',
                'severity': 'critical',
                'description': 'Uses exec/eval with string (code execution)'
            })
        
        # Character code obfuscation
        if re.search(r'chr\(\d+\)', code) or re.search(r'\\x[0-9a-fA-F]{2}', code):
            patterns.append({
                'type': 'character_encoding',
                'severity': 'high',
                'description': 'Uses character code obfuscation'
            })
        
        # ROT13 or similar encoding
        if 'codecs.decode' in code and 'rot' in code.lower():
            patterns.append({
                'type': 'rot_encoding',
                'severity': 'high',
                'description': 'Uses ROT encoding'
            })
        
        # Lambda obfuscation
        lambda_count = code.count('lambda')
        if lambda_count > 5:
            patterns.append({
                'type': 'excessive_lambdas',
                'severity': 'medium',
                'description': f'Excessive lambda usage ({lambda_count} instances)'
            })
        
        return {
            'is_obfuscated': len(patterns) > 0,
            'patterns': patterns
        }
    
    def _detect_hidden_characters(self, code: str) -> Dict:
        """Detect hidden Unicode characters and zero-width chars"""
        issues = []
        cleaned_code = code
        
        # Zero-width characters
        zero_width_chars = [
            '\u200B',  # Zero Width Space
            '\u200C',  # Zero Width Non-Joiner
            '\u200D',  # Zero Width Joiner
            '\uFEFF',  # Zero Width No-Break Space
            '\u2060',  # Word Joiner
        ]
        
        for char in zero_width_chars:
            if char in code:
                count = code.count(char)
                issues.append({
                    'type': 'zero_width_character',
                    'severity': 'high',
                    'description': f'Contains {count} hidden zero-width characters'
                })
                cleaned_code = cleaned_code.replace(char, '')
        
        # Right-to-Left Override (used to hide file extensions)
        if '\u202E' in code:
            issues.append({
                'type': 'rtl_override',
                'severity': 'critical',
                'description': 'Contains Right-to-Left override (file extension hiding)'
            })
            cleaned_code = cleaned_code.replace('\u202E', '')
        
        # Homoglyph detection (lookalike characters)
        homoglyphs = {
            'а': 'a', 'е': 'e', 'о': 'o',  # Cyrillic
            'ο': 'o', 'ν': 'v',  # Greek
        }
        
        for fake, real in homoglyphs.items():
            if fake in code:
                issues.append({
                    'type': 'homoglyph_character',
                    'severity': 'high',
                    'description': f'Contains lookalike character "{fake}" (appears as "{real}")'
                })
        
        return {
            'has_hidden': len(issues) > 0,
            'issues': issues,
            'cleaned_code': cleaned_code
        }
    
    def _detect_malicious_patterns(self, code: str, language: str) -> Dict:
        """Detect common malicious code patterns"""
        patterns = []
        score = 0
        
        # File system access
        file_ops = ['open(', 'os.remove', 'os.rmdir', 'shutil.rmtree', 'os.system']
        for op in file_ops:
            if op in code:
                patterns.append({
                    'type': 'file_operation',
                    'severity': 'medium',
                    'description': f'Performs file operation: {op}'
                })
                score += 15
        
        # Network access
        network_ops = ['urllib.request', 'requests.get', 'socket.socket', 'http.client']
        for op in network_ops:
            if op in code:
                patterns.append({
                    'type': 'network_access',
                    'severity': 'medium',
                    'description': f'Makes network requests: {op}'
                })
                score += 20
        
        # Process execution
        process_ops = ['subprocess.', 'os.popen', 'os.spawn', '__import__("os").system']
        for op in process_ops:
            if op in code:
                patterns.append({
                    'type': 'process_execution',
                    'severity': 'critical',
                    'description': f'Executes system commands: {op}'
                })
                score += 40
        
        # Encryption/cryptography (not always malicious but suspicious in unknown code)
        if any(x in code for x in ['Crypto.', 'cryptography.', 'AES', 'RSA']):
            patterns.append({
                'type': 'cryptography',
                'severity': 'medium',
                'description': 'Uses encryption libraries'
            })
            score += 10
        
        # Registry access (Windows)
        if 'winreg' in code or '_winreg' in code:
            patterns.append({
                'type': 'registry_access',
                'severity': 'high',
                'description': 'Accesses Windows registry'
            })
            score += 30
        
        # Anti-debugging
        anti_debug = ['ptrace', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent']
        for technique in anti_debug:
            if technique in code:
                patterns.append({
                    'type': 'anti_debugging',
                    'severity': 'critical',
                    'description': f'Contains anti-debugging technique: {technique}'
                })
                score += 45
        
        return {
            'is_suspicious': len(patterns) > 0,
            'patterns': patterns,
            'score': min(score, 100)
        }
    
    def _is_minified(self, code: str) -> bool:
        """Check if code is minified/compressed"""
        lines = code.split('\n')
        
        # Check average line length
        avg_line_length = sum(len(line) for line in lines) / max(len(lines), 1)
        
        # Minified code typically has very long lines
        if avg_line_length > 150:
            return True
        
        # Check for lack of whitespace
        code_without_strings = re.sub(r'["\'].*?["\']', '', code)
        whitespace_ratio = code_without_strings.count(' ') / max(len(code_without_strings), 1)
        
        if whitespace_ratio < 0.05:
            return True
        
        return False
    
    def _detect_encoding_tricks(self, code: str) -> Dict:
        """Detect encoding-based obfuscation"""
        tricks = []
        
        # Hex encoding
        if re.search(r'\\x[0-9a-fA-F]{2}', code):
            tricks.append({
                'type': 'hex_encoding',
                'severity': 'high',
                'description': 'Uses hexadecimal character encoding'
            })
        
        # Unicode escape sequences
        if re.search(r'\\u[0-9a-fA-F]{4}', code):
            tricks.append({
                'type': 'unicode_escape',
                'severity': 'medium',
                'description': 'Uses Unicode escape sequences'
            })
        
        # Octal encoding
        if re.search(r'\\[0-7]{3}', code):
            tricks.append({
                'type': 'octal_encoding',
                'severity': 'high',
                'description': 'Uses octal character encoding'
            })
        
        return {
            'has_tricks': len(tricks) > 0,
            'tricks': tricks
        }
    
    def _analyze_visual_layout(self, code: str) -> Dict:
        """Analyze code for visual layout issues"""
        issues = []
        reformatted = code
        
        lines = code.split('\n')
        
        # Check for extremely long lines (top-right overflow)
        long_lines = [(i+1, len(line)) for i, line in enumerate(lines) if len(line) > 120]
        
        if long_lines:
            issues.append({
                'type': 'long_lines',
                'severity': 'low',
                'description': f'{len(long_lines)} lines exceed 120 characters',
                'lines': [f'Line {ln}: {length} chars' for ln, length in long_lines[:5]]
            })
            
            # Wrap long lines
            reformatted_lines = []
            for line in lines:
                if len(line) > 120:
                    # Simple line wrapping (can be improved)
                    wrapped = self._wrap_line(line, 100)
                    reformatted_lines.extend(wrapped)
                else:
                    reformatted_lines.append(line)
            reformatted = '\n'.join(reformatted_lines)
        
        # Check for horizontal tabs (can cause alignment issues)
        if '\t' in code:
            issues.append({
                'type': 'tab_characters',
                'severity': 'low',
                'description': 'Contains tab characters (can cause display issues)'
            })
            reformatted = reformatted.replace('\t', '    ')
        
        return {
            'has_issues': len(issues) > 0,
            'issues': issues,
            'reformatted': reformatted
        }
    
    def _wrap_line(self, line: str, max_length: int) -> List[str]:
        """Wrap a long line into multiple lines"""
        if len(line) <= max_length:
            return [line]
        
        # Find good breaking points (after commas, operators, etc.)
        break_chars = [', ', ' + ', ' - ', ' * ', ' / ', ' and ', ' or ']
        
        wrapped = []
        current = line
        indent = len(line) - len(line.lstrip())
        
        while len(current) > max_length:
            # Find best break point
            best_break = -1
            for char in break_chars:
                pos = current[:max_length].rfind(char)
                if pos > best_break:
                    best_break = pos + len(char)
            
            if best_break == -1:
                # No good break point, force break
                best_break = max_length
            
            wrapped.append(current[:best_break])
            current = ' ' * (indent + 4) + current[best_break:].lstrip()
        
        wrapped.append(current)
        return wrapped
    
    def _reformat_code(self, code: str, language: str) -> str:
        """Reformat code for better visibility"""
        if language == 'python':
            try:
                # Use autopep8 if available
                import autopep8
                return autopep8.fix_code(code)
            except ImportError:
                # Basic formatting
                return self._basic_python_format(code)
        
        return code
    
    def _basic_python_format(self, code: str) -> str:
        """Basic Python code formatting"""
        lines = code.split('\n')
        formatted = []
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            
            # Decrease indent for closing brackets
            if stripped.startswith('}') or stripped.startswith(')') or stripped.startswith(']'):
                indent_level = max(0, indent_level - 1)
            
            # Add formatted line
            formatted.append('    ' * indent_level + stripped)
            
            # Increase indent after opening brackets or colons
            if stripped.endswith(':') or stripped.endswith('{') or stripped.endswith('('):
                indent_level += 1
        
        return '\n'.join(formatted)
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if analysis['threat_score'] >= 70:
            recommendations.append('🚨 DO NOT execute this code - high malware probability')
            recommendations.append('🗑️ Delete the file immediately')
            recommendations.append('📢 Report to IT security team')
        elif analysis['threat_score'] >= 40:
            recommendations.append('⚠️ Code contains suspicious patterns')
            recommendations.append('🔍 Manual security review required before execution')
            recommendations.append('🔒 Execute only in isolated sandbox environment')
        else:
            recommendations.append('ℹ️ Code has minor visibility issues')
            recommendations.append('📝 Review reformatted version for clarity')
        
        return recommendations

# Example usage
if __name__ == '__main__':
    checker = CodeVisibilityChecker()
    
    # Test with suspicious code
    suspicious_code = """
import base64
exec(base64.b64decode('aW1wb3J0IG9z'))
os.system('rm -rf /')
"""
    
    result = checker.analyze_code(suspicious_code, 'python')
    print("Analysis Results:")
    print(f"Safe: {result['is_safe']}")
    print(f"Threat Score: {result['threat_score']}")
    print(f"Issues: {result['issues']}")
    print(f"Recommendations: {result['recommendations']}")
