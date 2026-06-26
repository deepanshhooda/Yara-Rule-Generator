# YARA Rule Generator

Analyze malware samples using `file`, `strings`, `xxd`, and SHA256, then generate ready-to-use YARA rules via local AI.

## Features

- Collects file type, strings, hex patterns, and SHA256 hash
- AI-generated YARA rules with proper metadata and conditions
- Includes SHA256 hash in condition section
- Extracts interesting strings automatically (flag, password, shell, etc.)

## Usage

```bash
# Generate YARA rule from a sample
python yara-gen.py malware.bin

# Save to specific file
python yara-gen.py sample.exe -o report.yar
```

## Requirements

- `requests`
- `xxd`, `strings`, `file`, `shasum`
- `Ollama`
