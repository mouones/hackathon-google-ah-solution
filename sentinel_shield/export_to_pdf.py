"""
Export Sentinel Shield Documentation to PDF
Uses simple HTML export with print-to-PDF instructions
"""

import os
from pathlib import Path
from datetime import datetime

# Get paths
DOCS_DIR = Path(r"C:\Users\mns\.gemini\antigravity\brain\9f0fe554-ce8e-4850-ba96-db64ee27b8f0")
OUTPUT_DIR = Path(r"c:\hack\sentinel_shield")
OUTPUT_HTML = OUTPUT_DIR / "Sentinel_Shield_Complete_Documentation.html"

# Files to include in order
DOC_FILES = [
    "implementation_plan.md",
    "expanded_features.md", 
    "technical_specifications.md",
    "deployment_guide.md",
]

def read_markdown_file(filepath: Path) -> str:
    """Read markdown file content"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return ""

def combine_documents() -> str:
    """Combine all markdown documents"""
    combined = []
    
    # Add title page
    combined.append(f"""
# 🛡️ SENTINEL SHIELD
## Enterprise Security Platform
### Complete Documentation Package

---

**Version:** 1.0.0  
**Generated:** {datetime.now().strftime('%B %d, %Y at %H:%M')}  
**Classification:** Technical Architecture Document  
**Total Pages:** ~100+

---

## Table of Contents

1. **Architecture & Overview** - System design, modules, BMC
2. **Expanded Features (100+)** - Detailed feature specifications  
3. **Technical Specifications** - Datasets, APIs, infrastructure
4. **Deployment Guide** - Installation, configuration, operations

---

""")
    
    for i, doc_file in enumerate(DOC_FILES, 1):
        filepath = DOCS_DIR / doc_file
        if filepath.exists():
            print(f"📄 [{i}/{len(DOC_FILES)}] Adding: {doc_file}")
            content = read_markdown_file(filepath)
            combined.append(f"\n\n---\n\n# SECTION {i}: {doc_file.replace('.md', '').replace('_', ' ').upper()}\n\n---\n\n")
            combined.append(content)
        else:
            print(f"⚠️  Not found: {doc_file}")
    
    return "\n".join(combined)

def markdown_to_html(md_content: str) -> str:
    """Convert markdown to HTML with professional styling"""
    import markdown2
    
    # Convert markdown to HTML
    html_content = markdown2.markdown(
        md_content,
        extras=[
            'fenced-code-blocks',
            'tables',
            'code-friendly',
            'header-ids',
            'strike',
            'task_list',
            'cuddled-lists',
        ]
    )
    
    # Wrap in styled HTML document
    html_doc = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Shield - Enterprise Security Platform Documentation</title>
    <style>
        /* Print-optimized styles */
        @media print {{
            body {{
                font-size: 10pt;
            }}
            .no-print {{
                display: none;
            }}
            pre {{
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            h1, h2 {{
                page-break-after: avoid;
            }}
            table, pre {{
                page-break-inside: avoid;
            }}
        }}
        
        @page {{
            size: A4;
            margin: 1.5cm;
        }}
        
        * {{
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Roboto', sans-serif;
            font-size: 11pt;
            line-height: 1.65;
            color: #1a202c;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background: #fff;
        }}
        
        /* Headings */
        h1 {{
            color: #1a365d;
            font-size: 26pt;
            font-weight: 700;
            border-bottom: 3px solid #2b6cb0;
            padding-bottom: 12px;
            margin-top: 40px;
            margin-bottom: 20px;
        }}
        
        h2 {{
            color: #2c5282;
            font-size: 18pt;
            font-weight: 600;
            border-bottom: 2px solid #4299e1;
            padding-bottom: 8px;
            margin-top: 35px;
            margin-bottom: 15px;
        }}
        
        h3 {{
            color: #2b6cb0;
            font-size: 14pt;
            font-weight: 600;
            margin-top: 25px;
            margin-bottom: 12px;
        }}
        
        h4 {{
            color: #3182ce;
            font-size: 12pt;
            font-weight: 600;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        
        /* Tables */
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            font-size: 10pt;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        thead {{
            background: linear-gradient(135deg, #2c5282 0%, #2b6cb0 100%);
        }}
        
        th {{
            color: white;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            border: 1px solid #1a365d;
        }}
        
        td {{
            padding: 10px;
            border: 1px solid #e2e8f0;
            vertical-align: top;
        }}
        
        tr:nth-child(even) {{
            background-color: #f7fafc;
        }}
        
        tr:hover {{
            background-color: #edf2f7;
        }}
        
        /* Code */
        code {{
            background-color: #edf2f7;
            color: #c53030;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 9.5pt;
        }}
        
        pre {{
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
            color: #e2e8f0;
            padding: 18px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 9pt;
            line-height: 1.5;
            margin: 15px 0;
            border-left: 4px solid #4299e1;
        }}
        
        pre code {{
            background-color: transparent;
            color: inherit;
            padding: 0;
        }}
        
        /* Blockquotes */
        blockquote {{
            border-left: 4px solid #4299e1;
            margin: 20px 0;
            padding: 15px 20px;
            background: linear-gradient(135deg, #ebf8ff 0%, #e6fffa 100%);
            border-radius: 0 8px 8px 0;
            font-style: italic;
        }}
        
        /* Lists */
        ul, ol {{
            margin: 12px 0;
            padding-left: 28px;
        }}
        
        li {{
            margin: 6px 0;
        }}
        
        /* Links */
        a {{
            color: #2b6cb0;
            text-decoration: none;
        }}
        
        a:hover {{
            text-decoration: underline;
        }}
        
        /* Horizontal rules */
        hr {{
            border: none;
            height: 2px;
            background: linear-gradient(90deg, #2c5282, #4299e1, #2c5282);
            margin: 30px 0;
        }}
        
        /* Mermaid placeholder */
        .mermaid {{
            background: #f7fafc;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            font-style: italic;
            color: #718096;
            border: 1px dashed #cbd5e0;
        }}
        
        /* Cover styling */
        .cover {{
            text-align: center;
            padding: 100px 0;
            border-bottom: 3px solid #2c5282;
            margin-bottom: 40px;
        }}
        
        /* Print button */
        .print-btn {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #2c5282 0%, #2b6cb0 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 14pt;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(44,82,130,0.3);
            z-index: 1000;
        }}
        
        .print-btn:hover {{
            background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
        }}
        
        /* Section headers */
        .section-header {{
            background: linear-gradient(135deg, #2c5282 0%, #2b6cb0 100%);
            color: white;
            padding: 20px;
            margin: 40px -20px 30px -20px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <button class="print-btn no-print" onclick="window.print()">📄 Print / Save as PDF</button>
    
    {html_content}
    
    <script>
        // Handle mermaid diagrams (placeholder)
        document.querySelectorAll('code.language-mermaid').forEach(el => {{
            const parent = el.parentElement;
            const div = document.createElement('div');
            div.className = 'mermaid';
            div.textContent = '[Mermaid Diagram - View in browser for interactive version]';
            parent.replaceWith(div);
        }});
    </script>
</body>
</html>
"""
    return html_doc

def main():
    print("=" * 60)
    print("🛡️  SENTINEL SHIELD - DOCUMENTATION EXPORT")
    print("=" * 60)
    
    # Combine all documents
    print("\n📚 Combining documentation...")
    combined_md = combine_documents()
    print(f"   Total size: {len(combined_md):,} characters")
    
    # Convert to HTML
    print("\n🔄 Converting to HTML...")
    html_content = markdown_to_html(combined_md)
    
    # Save HTML
    print(f"\n💾 Saving to: {OUTPUT_HTML}")
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    file_size = OUTPUT_HTML.stat().st_size / 1024
    print(f"   File size: {file_size:.1f} KB")
    
    print("\n" + "=" * 60)
    print("✅ EXPORT COMPLETE!")
    print("=" * 60)
    print(f"\n📄 HTML File: {OUTPUT_HTML}")
    print("\n📋 To create PDF:")
    print("   1. Open the HTML file in Chrome/Edge")
    print("   2. Click 'Print / Save as PDF' button (top right)")
    print("   3. Or press Ctrl+P and select 'Save as PDF'")
    print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
