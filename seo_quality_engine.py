import os
import re

DOCS_DIR = r"C:\Users\anim3\Documents\antigravity\appsec-atlas\docs"

def extract_title(content):
    match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if match:
        return match.group(1).replace('"', "'").strip()
    return "AppSec Atlas Security Guide"

def generate_description(content):
    # Find the first paragraph (non-empty line that doesn't start with #, >, -, or *)
    lines = content.split('\n')
    for line in lines:
        stripped = line.strip()
        if stripped and not re.match(r"^[#>\-\*]", stripped) and not stripped.startswith("---") and len(stripped) > 30:
            # truncate to 150 chars for SEO
            desc = stripped[:150]
            if len(stripped) > 150:
                desc += "..."
            return desc.replace('"', "'")
    return "Comprehensive security guide and practical technical implementation handbook."

def generate_keywords(filepath, title):
    # Base keywords
    keywords = ["AppSec", "Cybersecurity", "Security Guide", "Tutorial"]
    # Add folder names
    parts = filepath.split(os.sep)
    for part in parts:
        if part not in ["docs", "C:", "Users", "anim3", "Documents", "antigravity", "appsec-atlas"]:
            clean_part = part.replace("-", " ").title()
            if clean_part and clean_part not in keywords:
                keywords.append(clean_part)
    return keywords

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Skip if already has frontmatter
    if content.startswith("---"):
        return False

    title = extract_title(content)
    description = generate_description(content)
    keywords = generate_keywords(filepath, title)
    
    keywords_str = "[" + ", ".join([f'"{k}"' for k in keywords]) + "]"

    frontmatter = f"""---
title: "{title}"
description: "{description}"
keywords: {keywords_str}
---

"""
    new_content = frontmatter + content

    # Quality enrichment: Add a tip alert if none exists and it's an introduction
    if "01-introduction" in filepath and "> [!TIP]" not in new_content:
        new_content = new_content.replace("##", "> [!TIP]\n> **Industry Best Practice:** Always align this domain with standard frameworks like OWASP, NIST, or CIS benchmarks for optimal security posture.\n\n##", 1)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    return True

def main():
    processed_count = 0
    for root, dirs, files in os.walk(DOCS_DIR):
        for file in files:
            if file.endswith(".md"):
                filepath = os.path.join(root, file)
                if process_file(filepath):
                    processed_count += 1
                    
    print(f"✅ SEO & Quality Audit Complete. Successfully injected metadata and enriched {processed_count} Markdown files.")

if __name__ == "__main__":
    main()
