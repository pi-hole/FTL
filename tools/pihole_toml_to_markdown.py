import re
from pathlib import Path

def parse_toml_with_comments(filepath):
    """
    Parse a TOML file with comments and generate a Markdown documentation string.

    Args:
        filepath (str or Path): Path to the TOML file.

    Returns:
        str: Markdown-formatted documentation.
    """
    with open(filepath, encoding='utf-8') as f:
        lines = f.readlines()

    # Start with a Markdown header and introductory documentation block
    documentation = ["""<!-- markdownlint-disable MD033 -->
# Pi-hole FTL Configuration Reference

This page documents the available options of `pihole-FTL`. They are typically managed via the [TOML](https://toml.io/)-formatted configuration file `/etc/pihole/pihole.toml`. This file may be edited directly or you can use the command line (CLI) option, the web interface, the application programming interface (API) or environment variables.

Using the web interface, the API or the CLI is preferred as they can do error checking for you, trying to prevent any incompatible options which could prevent FTL from starting on a severely broken configuration.

To edit with the command line, use the format `key.name=value`, e.g:

```text
sudo pihole-FTL --config dns.dnssec=true
```

!!! note "Environment Variables"
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
"""]
    section_stack = []      # Tracks the current TOML section(s)
    comment_buffer = []     # Collects comments preceding a key
    in_config = False       # True after the first section header

    for line in lines:
        stripped = line.strip()

        # Section header: [section]
        if re.match(r'^\[.*\]$', stripped):
            in_config = True
            section_stack = [stripped.strip('[]')]
            documentation.append(f"## [{'.'.join(section_stack)}]\n")
            continue

        # Array of tables: [[section]]
        elif re.match(r'^\[\[.*\]\]$', stripped):
            in_config = True
            section_stack = [stripped.strip('[]')]
            documentation.append(f"## [{'.'.join(section_stack)}]\n")
            continue

        # Comment line
        elif stripped.startswith('#'):
            if in_config:
                comment_buffer.append(stripped.lstrip('#').strip())
            continue

        # Key-value line inside a section
        elif '=' in stripped and in_config:
            key, value = map(str.strip, stripped.split('=', 1))
            documentation.append(f"### `{key}`\n")
            if comment_buffer:
                adjusted_comments = []
                table_rows = []
                in_table = False
                i = 0
                # Process each comment line for formatting and tables
                while i < len(comment_buffer):
                    line = comment_buffer[i]

                    # Fix malformed emphasis due to underscores or asterisks
                    line = re.sub(r'\b(_[a-zA-Z0-9.-]+)', r'`\1`', line)
                    line = re.sub(r'\*\.[a-zA-Z0-9]+', lambda m: f"`{m.group(0)}`", line)

                    # Avoid MD052 by escaping opening brackets
                    line = line.replace("[", "\[")

                    # Escape angle brackets
                    line = line.replace("<", "&lt;").replace(">", "&gt;")

                    is_bullet = line.lstrip().startswith("- ")
                    next_line = comment_buffer[i + 1] if i + 1 < len(comment_buffer) else ""

                    # Bold for "Possible values are:"
                    if line.lower().startswith("possible values are:"):
                        adjusted_comments.append(f"**{line}**\n")
                        i += 1
                        continue

                    # Table row for bullet points with quoted values or integer values
                    if is_bullet and (re.match(r'-\s+\".*\"', line) or re.match(r'-\s+\d$', line)):
                        value_part = re.search(r'\"(.*?)\"|(\d)', line).group(1)
                        description_lines = []
                        j = i + 1
                        # Collect description lines for this value
                        while j < len(comment_buffer) and not comment_buffer[j].lstrip().startswith("- "):
                            description_lines.append(comment_buffer[j].strip())
                            j += 1
                        table_rows.append((value_part, " ".join(description_lines)))
                        i = j
                        in_table = True
                        continue

                    # Regular bullet points
                    if is_bullet:
                        if len(adjusted_comments) > 0 and adjusted_comments[-1].strip() != "":
                            adjusted_comments.append("")  # blank line before
                        adjusted_comments.append(line)
                        if (i + 1 >= len(comment_buffer)) or (not comment_buffer[i + 1].lstrip().startswith("- ")):
                            adjusted_comments.append("")  # blank line after
                        i += 1
                        continue

                    # Regular comment line
                    adjusted_comments.append(line)
                    i += 1

                # If a table was detected, render it as HTML
                if in_table:
                    adjusted_comments.append("")
                    adjusted_comments.append("<table>")
                    adjusted_comments.append("<thead><tr><th style=\"white-space: nowrap\">Value</th><th>Description</th></tr></thead>")
                    adjusted_comments.append("<tbody>")
                    for val, desc in table_rows:
                        adjusted_comments.append(f"<tr><td><code style='white-space: nowrap'>{val}</code></td><td>{desc}</td></tr>")
                    adjusted_comments.append("</tbody>")
                    adjusted_comments.append("</table>\n")

                documentation.append("\n".join(adjusted_comments))
                documentation.append("")  # spacer after comment block
            documentation.append(f"**Default value:** `{value}`\n")

            # Compose full key for CLI/env var examples
            full_key = ".".join(section_stack + [key])
            env_var = "FTLCONF_" + "_".join(section_stack + [key])

            # TOML example tab
            documentation.append(f"=== \"TOML\"")
            documentation.append("    ```toml")
            documentation.append(f"    [{'.'.join(section_stack)}]")
            documentation.append(f"      {key} = {value}")
            documentation.append("    ```")

            # CLI example tab
            documentation.append(f"=== \"CLI\"")
            documentation.append("    ```shell")
            documentation.append(f"    sudo pihole-FTL --config {full_key}={value}")
            documentation.append("    ```")

            # Environment variable example tab (for Docker Compose)
            documentation.append(f"=== \"Environment (Docker Compose)\"")
            documentation.append("    ```yaml")
            documentation.append("    environment:")
            documentation.append(f"      {env_var}: {value}")
            documentation.append("    ```\n")

            comment_buffer = []

    return "\n".join(documentation)

def write_markdown_doc(input_toml_path, output_md_path):
    """
    Generate Markdown documentation from a TOML file and write it to a file.

    Args:
        input_toml_path (str or Path): Path to the input TOML file.
        output_md_path (str or Path): Path to the output Markdown file.
    """
    markdown = parse_toml_with_comments(input_toml_path)
    Path(output_md_path).write_text(markdown, encoding='utf-8')
    print(f"Documentation written to {output_md_path}")

if __name__ == "__main__":
    import sys
    # Expect exactly two arguments: input TOML and output Markdown
    if len(sys.argv) != 3:
        print("Usage: python pihole_toml_to_markdown.py <input.toml> <output.md>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    write_markdown_doc(input_path, output_path)
