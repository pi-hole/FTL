import re
from pathlib import Path

def parse_toml_with_comments(filepath):
    with open(filepath, encoding='utf-8') as f:
        lines = f.readlines()

    documentation = ["""
# Pi-hole FTL Configuration Reference

This page documents the available options in the `pihole-FTL.conf` file, which is typically managed via the TOML-formatted configuration file:

```text\n/etc/pihole/pihole.toml\n```

The file can be edited directly, however you can also use the command line option or the web interface.

To edit with the command line, use the format `key.name=value`, e.g:

```text\npihole-FTL --config dns.dnssec=true\n```

!!! note
    **⚙️ Configuration Precedence**

    Every Pi-hole setting in this file can be overridden using an environment variable.
    This is especially common in Docker deployments.

    Environment variable names follow the format:

    ```text
    FTLCONF_<section>_<key>
    ```

    For example:

    ```text
    FTLCONF_dns_upstreams
    FTLCONF_database_DBimport
    ```

    ⚠️ **If a setting is defined via an environment variable, it becomes read-only.**
    You will not be able to override it through the TOML file, the command line, or the web interface until the variable is removed from the environment.

---
<!-- markdownlint-disable-file MD034 -->
"""
    ]
    section_stack = []
    comment_buffer = []
    in_config = False  # <-- New flag to skip file header comments

    for line in lines:
        stripped = line.strip()

        # Handle section headers
        if re.match(r'^\[.*\]$', stripped):
            in_config = True  # <-- Start processing comments now
            section_stack = [stripped.strip('[]')]
            documentation.append(f"## [{'.'.join(section_stack)}]\n")
            continue

        # Handle nested section headers
        elif re.match(r'^\[\[.*\]\]$', stripped):
            in_config = True
            section_stack = [stripped.strip('[]')]
            documentation.append(f"## [{'.'.join(section_stack)}]\n")
            continue

        # Skip all comments before first section
        elif stripped.startswith('#'):
            if in_config:
                comment_buffer.append(stripped.lstrip('#').strip())
            continue

        # Handle key-value pairs
        elif '=' in stripped and in_config:
            key, value = map(str.strip, stripped.split('=', 1))
            documentation.append(f"### `{key}`\n")
            if comment_buffer:
                adjusted_comments = []

                for i, line in enumerate(comment_buffer):
                    is_bullet = line.lstrip().startswith("-")
                    prev_is_bullet = (
                        i > 0 and comment_buffer[i - 1].lstrip().startswith("-")
                    )
                    prev_is_blank = i > 0 and comment_buffer[i - 1].strip() == ""

                    # Insert blank line before bullet if needed
                    if is_bullet and not prev_is_bullet and not prev_is_blank:
                        adjusted_comments.append("")

                    # Escape angle brackets
                    line = line.replace("<", "&lt;").replace(">", "&gt;")

                    # Bold + line break after "Possible values are:"
                    if line.lower().startswith("possible values are:"):
                        line = f"**{line}**"
                        adjusted_comments.append(line)
                        adjusted_comments.append("")  # blank line after
                    else:
                        adjusted_comments.append(line)

                documentation.append("\n".join(adjusted_comments))
                documentation.append("")  # spacer after comment block
            documentation.append(f"**Default value:** `{value}`\n")
            comment_buffer = []

    return "\n".join(documentation)

def write_markdown_doc(input_toml_path, output_md_path):
    markdown = parse_toml_with_comments(input_toml_path)
    Path(output_md_path).write_text(markdown, encoding='utf-8')
    print(f"Documentation written to {output_md_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python pihole_toml_to_markdown.py <input.toml> <output.md>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    write_markdown_doc(input_path, output_path)