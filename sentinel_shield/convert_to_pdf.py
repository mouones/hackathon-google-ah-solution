"""
Sentinel Shield - Markdown to PDF Converter
Converts presentation slides to professional PDF format
"""

import os
import sys
from pathlib import Path

def convert_with_pandoc(input_file, output_file):
    """Convert using Pandoc (best quality)"""
    try:
        import subprocess
        
        # Check if pandoc is installed
        result = subprocess.run(['pandoc', '--version'], 
                              capture_output=True, 
                              text=True)
        
        if result.returncode != 0:
            return False
        
        print("✓ Pandoc found")
        print("Converting with Pandoc...")
        
        # Convert with nice formatting
        cmd = [
            'pandoc',
            input_file,
            '-o', output_file,
            '--pdf-engine=xelatex',
            '--variable', 'geometry:margin=1in',
            '--variable', 'fontsize=12pt',
            '--toc',
            '--toc-depth=2',
            '--highlight-style=tango'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✓ PDF created successfully: {output_file}")
            return True
        else:
            print(f"✗ Pandoc error: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("✗ Pandoc not found")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def convert_with_markdown_pdf(input_file, output_file):
    """Convert using markdown-pdf Python package"""
    try:
        from markdown_pdf import MarkdownPdf, Section
        
        print("✓ markdown-pdf found")
        print("Converting with markdown-pdf...")
        
        pdf = MarkdownPdf()
        pdf.add_section(Section(input_file))
        pdf.save(output_file)
        
        print(f"✓ PDF created successfully: {output_file}")
        return True
        
    except ImportError:
        print("✗ markdown-pdf not installed")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def convert_with_weasyprint(input_file, output_file):
    """Convert using markdown + weasyprint"""
    try:
        import markdown
        from weasyprint import HTML, CSS
        from weasyprint.text.fonts import FontConfiguration
        
        print("✓ markdown + weasyprint found")
        print("Converting with weasyprint...")
        
        # Read markdown
        with open(input_file, 'r', encoding='utf-8') as f:
            md_content = f.read()
        
        # Convert to HTML
        html_content = markdown.markdown(
            md_content,
            extensions=[
                'extra',
                'codehilite',
                'tables',
                'toc',
                'fenced_code'
            ]
        )
        
        # Wrap in HTML template
        html_full = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        @page {{
            size: Letter;
            margin: 0.75in;
        }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.6;
            color: #333;
        }}
        h1 {{
            color: #2c5282;
            border-bottom: 3px solid #2c5282;
            padding-bottom: 10px;
            page-break-before: always;
        }}
        h1:first-of-type {{
            page-break-before: avoid;
        }}
        h2 {{
            color: #2c5282;
            margin-top: 30px;
        }}
        h3 {{
            color: #4a5568;
        }}
        code {{
            background: #f7fafc;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', monospace;
            font-size: 10pt;
        }}
        pre {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 9pt;
        }}
        pre code {{
            background: transparent;
            color: #e2e8f0;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            font-size: 10pt;
        }}
        th, td {{
            border: 1px solid #cbd5e0;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background: #2c5282;
            color: white;
            font-weight: 600;
        }}
        tr:nth-child(even) {{
            background: #f7fafc;
        }}
        blockquote {{
            border-left: 4px solid #2c5282;
            padding-left: 15px;
            color: #4a5568;
            font-style: italic;
        }}
        hr {{
            border: none;
            border-top: 2px solid #e2e8f0;
            margin: 30px 0;
        }}
        ul, ol {{
            margin: 10px 0;
            padding-left: 25px;
        }}
        li {{
            margin: 5px 0;
        }}
        .page-break {{
            page-break-after: always;
        }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""
        
        # Convert to PDF
        font_config = FontConfiguration()
        HTML(string=html_full).write_pdf(
            output_file,
            font_config=font_config
        )
        
        print(f"✓ PDF created successfully: {output_file}")
        return True
        
    except ImportError as e:
        print(f"✗ Missing package: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def convert_with_pypandoc(input_file, output_file):
    """Convert using pypandoc wrapper"""
    try:
        import pypandoc
        
        print("✓ pypandoc found")
        print("Converting with pypandoc...")
        
        pypandoc.convert_file(
            input_file,
            'pdf',
            outputfile=output_file,
            extra_args=[
                '--pdf-engine=xelatex',
                '--variable', 'geometry:margin=1in',
                '--variable', 'fontsize=12pt',
                '--toc'
            ]
        )
        
        print(f"✓ PDF created successfully: {output_file}")
        return True
        
    except ImportError:
        print("✗ pypandoc not installed")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def main():
    print("=" * 60)
    print("  Sentinel Shield - Markdown to PDF Converter")
    print("=" * 60)
    print()
    
    # Input/output files
    input_file = "PRESENTATION_SLIDES.md"
    output_file = "Sentinel_Shield_Presentation.pdf"
    
    if not os.path.exists(input_file):
        print(f"✗ Error: {input_file} not found!")
        print("  Make sure you're running this from the sentinel_shield directory")
        sys.exit(1)
    
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print()
    
    # Try conversion methods in order of preference
    methods = [
        ("Pandoc (recommended)", convert_with_pandoc),
        ("WeasyPrint", convert_with_weasyprint),
        ("pypandoc", convert_with_pypandoc),
        ("markdown-pdf", convert_with_markdown_pdf),
    ]
    
    print("Trying conversion methods...")
    print()
    
    for method_name, method_func in methods:
        print(f"Trying {method_name}...")
        if method_func(input_file, output_file):
            print()
            print("=" * 60)
            print("  ✓ SUCCESS!")
            print("=" * 60)
            print(f"PDF created: {output_file}")
            print(f"Size: {os.path.getsize(output_file) / 1024:.1f} KB")
            return
        print()
    
    # If all methods failed
    print("=" * 60)
    print("  ✗ CONVERSION FAILED")
    print("=" * 60)
    print()
    print("None of the conversion methods worked.")
    print()
    print("Install required packages:")
    print()
    print("Option 1 (Recommended): Install Pandoc")
    print("  Windows: choco install pandoc")
    print("  Or download: https://pandoc.org/installing.html")
    print()
    print("Option 2: Install Python packages")
    print("  pip install markdown weasyprint")
    print("  or")
    print("  pip install pypandoc")
    print()
    sys.exit(1)


if __name__ == "__main__":
    main()
