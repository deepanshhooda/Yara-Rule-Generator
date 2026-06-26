#!/usr/bin/env python3
"""YARA Rule Generator — analyze malware samples and generate YARA rules via AI."""

import sys
import json
import argparse
import subprocess
from pathlib import Path


def analyze_sample(filepath):
    """Run analysis tools on a sample and collect features."""
    info = {'file': str(filepath), 'size': Path(filepath).stat().st_size, 'type': '', 'strings': [], 'hex_patterns': []}

    try:
        r = subprocess.run(['file', str(filepath)], capture_output=True, text=True, timeout=10)
        info['type'] = r.stdout.strip()
    except:
        pass

    try:
        r = subprocess.run(['xxd', '-l', '1024', str(filepath)], capture_output=True, text=True, timeout=10)
        hex_lines = r.stdout.strip().split('\n')[:20]
        for line in hex_lines:
            parts = line.split()
            if len(parts) > 1:
                info['hex_patterns'].append(' '.join(parts[1:-1]))
    except:
        pass

    try:
        r = subprocess.run(['strings', '-n', '6', str(filepath)], capture_output=True, text=True, timeout=30)
        interesting = []
        for s in r.stdout.split('\n'):
            s = s.strip()
            if 6 <= len(s) <= 64 and s.isprintable():
                interesting.append(s)
        info['strings'] = interesting[:50]
    except:
        pass

    try:
        r = subprocess.run(['shasum', '-a', '256', str(filepath)], capture_output=True, text=True, timeout=5)
        info['sha256'] = r.stdout.split()[0]
    except:
        pass

    return info


def generate_yara(info, ollama_url="http://localhost:11434"):
    """Generate YARA rule via AI."""
    prompt = f"""You are a YARA rule author. Generate a high-quality YARA rule for this malware sample.

Analysis:
- File: {info['file']}
- Type: {info['type'][:100]}
- SHA256: {info.get('sha256', 'N/A')}
- Size: {info['size']:,} bytes

Interesting strings (first 30):
{chr(10).join('  - ' + s for s in info['strings'][:30])}

Hex patterns (first 10):
{chr(10).join('  - ' + s for s in info['hex_patterns'][:10])}

Generate a complete YARA rule that:
1. Has a descriptive rule name based on the sample
2. Uses $a, $b, $c etc. for strings
3. Includes the SHA256 as a hash condition
4. Has proper metadata (author, date, description, hash)
5. Uses both string and condition sections

Return ONLY the YARA rule, no explanation."""

    try:
        import requests
        r = requests.post(f"{ollama_url}/api/chat", json={
            "model": "llama3.2:3b",
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }, timeout=120)
        if r.ok:
            content = r.json().get('message', {}).get('content', '')
            if '```' in content:
                content = content.split('```')[1] if content.count('```') >= 2 else content
                if content.startswith('yara'):
                    content = content.split('\n', 1)[-1]
            return content.strip()
        return f"# Error: Ollama returned {r.status_code}"
    except Exception as e:
        return f"# Error: {e}"


def main():
    parser = argparse.ArgumentParser(description='YARA Rule Generator')
    parser.add_argument('sample', help='Malware sample file to analyze')
    parser.add_argument('--ollama', default='http://localhost:11434', help='Ollama URL')
    parser.add_argument('--output', '-o', help='Output .yar file')
    args = parser.parse_args()

    if not Path(args.sample).exists():
        print(f"File not found: {args.sample}")
        sys.exit(1)

    print(f"YARA Rule Generator")
    print(f"{'='*50}")
    print(f"Analyzing sample: {args.sample}")

    info = analyze_sample(args.sample)

    print(f"  Type: {info['type'][:60]}")
    print(f"  Size: {info['size']:,} bytes")
    print(f"  SHA256: {info.get('sha256', 'N/A')}")
    print(f"  Strings found: {len(info['strings'])}")

    print(f"\nGenerating YARA rule via AI...")
    rule = generate_yara(info, args.ollama)

    print(f"\n{'='*50}")
    print(f"  GENERATED YARA RULE")
    print(f"{'='*50}\n")
    print(rule)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(rule)
        print(f"\nRule saved: {args.output}")
    else:
        out_name = Path(args.sample).stem + '.yar'
        with open(out_name, 'w') as f:
            f.write(rule)
        print(f"\nRule saved: {out_name}")


if __name__ == '__main__':
    main()
