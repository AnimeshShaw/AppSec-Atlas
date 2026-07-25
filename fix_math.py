import os, re, glob

def fix_math(text):
    # Fix $$...$$ not already in backticks
    text = re.sub(r'(?<!`)\$\$(.*?)\$\$(?!`)', r'```math\n\1\n```', text, flags=re.DOTALL)
    # Fix $...$ not already in backticks, handling cases where it's not a dollar amount
    # but we will just wrap all $...$ in backticks.
    text = re.sub(r'(?<!`)\$(.*?)\$(?!`)', r'`$\1$`', text)
    return text

files = glob.glob('docs/**/*.md', recursive=True)
count = 0
for f in files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    new_content = fix_math(content)
    if new_content != content:
        with open(f, 'w', encoding='utf-8') as file:
            file.write(new_content)
        count += 1
        print(f'Fixed {f}')
print(f'Total fixed: {count}')
