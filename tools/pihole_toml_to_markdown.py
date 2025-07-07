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
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    # Start with a Markdown header and introductory documentation block
    documentation = [
        """<!-- markdownlint-disable MD033 -->
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
"""
    ]
    section_stack = []
    comment_buffer = []
    in_config = False  # <-- New flag to skip file header comments

    lines_iter = iter(lines)
    for line in lines_iter:
        stripped = line.strip()

        # Handle section headers
        if re.match(r"^\[.*\]$", stripped):
            in_config = True  # <-- Start processing comments now
            section_stack = [stripped.strip("[]")]
            documentation.append(f"\n## `[{'.'.join(section_stack)}]`\n")
            continue

        # If we are in a config section, start buffering comments
        elif stripped.startswith("#"):
            if in_config:
                comment_buffer.append(stripped.lstrip("#").strip())
            continue

        # Handle key-value pairs
        elif "=" in stripped and in_config:
            key, value = map(str.strip, stripped.split("=", 1))
            value_lines = [value]

            # Check if value is a multi-line array
            if value.startswith("[") and not value.endswith("]"):
                # Multi-line array
                while not value_lines[-1].strip().endswith("]"):
                    next_line = next(lines_iter).rstrip("\n")
                    value_lines.append(next_line)
                value = "\n".join(value_lines)

            else:
                value = value_lines[0]

            documentation.append(f"### `{key}`\n")

            # Process the comments collected for this key
            if comment_buffer:
                adjusted_comments = []

                i = 0
                while i < len(comment_buffer):
                    line = comment_buffer[i]
                    is_bullet = line.lstrip().startswith("-")
                    prev_is_bullet = i > 0 and comment_buffer[i - 1].lstrip().startswith("-")
                    prev_is_blank = i > 0 and comment_buffer[i - 1].strip() == ""

                    # Fix malformed emphasis due to underscores or asterisks
                    line = re.sub(r'\b(_[a-zA-Z0-9.-]+)', r'`\1`', line)
                    line = re.sub(r'\*\.[a-zA-Z0-9]+', lambda m: f"`{m.group(0)}`", line)

                    # Bold "Allowed values are:"
                    line = re.sub(
                        r'(^|\s)(Allowed values are:)',
                        r'\1**Allowed values are:**',
                        line
                    )

                    # Bold "Example:"
                    line = re.sub(
                        r'(^|\s)(Example:)',
                        r'\1**Example:**',
                        line
                    )

                    # Insert blank line before bullet if needed
                    if is_bullet and not prev_is_bullet and not prev_is_blank:
                        adjusted_comments.append("")

                    # Default: just append the line
                    adjusted_comments.append(line)
                    i += 1

                documentation.append(wrap_examples_and_allowed_values("\n".join(adjusted_comments)))
                documentation.append("")  # spacer after comment block
            # Format default value for Markdown
            if "\n" in value:
                documentation.append("**Default value:**")
                documentation.append("")
                documentation.append("```toml")
                documentation.append(f"{value}")
                documentation.append("```")
                documentation.append("")
            else:
                documentation.append(f"**Default value:** `{value}`\n")

            # Compose full key for CLI/env var examples
            full_key = ".".join(section_stack + [key])
            env_var = "FTLCONF_" + "_".join(section_stack + [key])

            # TOML example tab
            documentation.append(f'=== "TOML"')
            documentation.append("    ```toml")
            documentation.append(f"    [{'.'.join(section_stack)}]")
            # Indent multi-line values for TOML block
            if "\n" in value:
                indented_value = "\n".join("      " + v for v in value.splitlines())
                documentation.append(f"      {key} = {indented_value}")
            else:
                documentation.append(f"      {key} = {value}")
            documentation.append("    ```")

            # CLI example tab
            documentation.append(f'=== "CLI"')
            documentation.append("    ```shell")
            if "\n" in value and value.strip().startswith("["):
                # Flatten multi-line array to single line for CLI
                array_str = "".join(value.split())
                documentation.append(f"    sudo pihole-FTL --config {full_key}='{array_str}'")
            else:
                documentation.append(f"    sudo pihole-FTL --config {full_key}={value}")
            documentation.append("    ```")

            # Environment variable example tab (for Docker Compose)
            documentation.append(f'=== "Environment (Docker Compose)"')
            documentation.append("    ```yaml")
            documentation.append("    environment:")
            yaml_value = value.replace('"',"'")
            if "\n" in yaml_value:
                yaml_value = f"|\n        " + "\n        ".join(yaml_value.splitlines())
            documentation.append(f"      {env_var}: {yaml_value}")
            documentation.append("    ```\n")
            comment_buffer = []

    return "\n".join(documentation)

def wrap_examples_and_allowed_values(line):
    """
    Wrap specific patterns in backticks:
    - Complete arrays: [ "example" ] -> `[ "example" ]`
    - Quoted strings: "example" -> `"example"`
    - Angle brackets: <example> -> `<example>`

    Ensures no nested backticks appear within wrapped content.
    """

    # Process other patterns
    result = ''
    i = 0
    in_backticks = False

    while i < len(line):
        # Skip content already in backticks
        if in_backticks:
            if line[i:i+1] == '`':
                in_backticks = False
            result += line[i]
            i += 1
            continue

        # Look for patterns to wrap
        if line[i:i+1] == '"':
            # Find the matching closing quote
            j = i + 1
            while j < len(line) and line[j] != '"':
                j += 1
            if j < len(line):  # Found closing quote
                quoted_content = line[i:j+1]
                result += f'`{quoted_content}`'
                i = j + 1
                in_backticks = False

        elif line[i:i+1] == '<':
            # Find the matching closing angle bracket
            j = i + 1
            while j < len(line) and line[j] != '>':
                j += 1
            if j < len(line):  # Found closing bracket
                angle_content = line[i:j+1]
                result += f'`{angle_content}`'
                i = j + 1
                in_backticks = False
            else:  # No closing bracket found
                result += line[i]
                i += 1

        elif line[i:i+1] == '[':
            # Track nested square brackets
            j = i + 1
            bracket_count = 1
            while j < len(line):
                if line[j] == '[':
                    bracket_count += 1
                elif line[j] == ']':
                    bracket_count -= 1
                if bracket_count == 0:
                    break
                j += 1
            if bracket_count == 0 and j < len(line):  # Found matching closing bracket
                square_content = line[i:j+1]
                result += f'`{square_content}`'
                i = j + 1
                in_backticks = False

            else:  # No matching closing bracket found
                result += line[i]
                i += 1

        else:
            result += line[i]
            i += 1

    return result

def write_markdown_doc(input_toml_path, output_md_path):
    """
    Generate Markdown documentation from a TOML file and write it to a file.

    Args:
        input_toml_path (str or Path): Path to the input TOML file.
        output_md_path (str or Path): Path to the output Markdown file.
    """
    markdown = parse_toml_with_comments(input_toml_path)
    Path(output_md_path).write_text(markdown, encoding="utf-8")
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


