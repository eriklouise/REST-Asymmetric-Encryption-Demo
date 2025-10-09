#*********************************************************************************
#                                                                                *
# This file is part of the "CTM REST Asymmetric key demo" project.               *
# Use it at your own risk                                                        *
# Distributed under Apache 2.0 license                                           *
#                                                                                *
# Written by Erik LOUISE                                                         *
# Copyright © 2025 Thales Group                                                  *
#                                                                                *
#*********************************************************************************

# OBJECTIVE :
# - compare the original clear payload with the decrypted payload
# - The original clear payload is stored in ./payload/clear_payload.txt
# - The decrypted payload is stored in ./payload/unencrypted_payload.txt

import config
import os
import difflib

CLEAR_PAYLOAD_FILE = config.CLEAR_PAYLOAD_FILE
UNENCRYPTED_PAYLOAD_FILE = config.UNENCRYPTED_PAYLOAD_FILE

def read_file_with_line_ending_info(filepath):
    try:
        # Read as binary first to detect line endings
        with open(filepath, 'rb') as f:
            raw_content = f.read()
        
        # Detect line ending type
        has_crlf = b'\r\n' in raw_content
        has_lf = b'\n' in raw_content and not has_crlf
        has_cr = b'\r' in raw_content and not has_crlf
        
        line_ending_type = "Unknown"
        if has_crlf:
            line_ending_type = "Windows (CRLF)"
        elif has_lf:
            line_ending_type = "Unix (LF)"
        elif has_cr:
            line_ending_type = "Classic Mac (CR)"
        
        # Read as text with universal newlines
        with open(filepath, 'r', encoding='utf-8', newline='') as f:
            text_content = f.read()
        
        # Split into lines preserving line endings
        lines_with_endings = text_content.splitlines(keepends=True)
        lines_normalized = text_content.splitlines(keepends=False)
        
        return {
            'raw_bytes': raw_content,
            'text_content': text_content,
            'lines_with_endings': lines_with_endings,
            'lines_normalized': lines_normalized,
            'line_ending_type': line_ending_type,
            'file_size': len(raw_content),
            'line_count': len(lines_normalized)
        }
    except Exception as e:
        return {'error': str(e)}

def compare_files(file1_path, file2_path):
    
    # Read both files
    file1_info = read_file_with_line_ending_info(file1_path)
    file2_info = read_file_with_line_ending_info(file2_path)
    
    # Check for read errors
    if 'error' in file1_info:
        print(f"Error reading file 1: {file1_info['error']}")
        return
    if 'error' in file2_info:
        print(f"Error reading file 2: {file2_info['error']}")
        return
    
    # File size comparison
    print(f"File sizes:")
    print(f"  Clear payload: {file1_info['file_size']} bytes")
    print(f"  Unencrypted payload: {file2_info['file_size']} bytes")
    
    # Line ending analysis
    print(f"\nLine ending types:")
    print(f"  Clear payload: {file1_info['line_ending_type']}")
    print(f"  Unencrypted payload: {file2_info['line_ending_type']}")
    
    # Line count
    print(f"\nLine counts:")
    print(f"  Clear payload: {file1_info['line_count']} lines")
    print(f"  Unencrypted payload: {file2_info['line_count']} lines")
    
    # Binary comparison
    print(f"\nBinary comparison:")
    if file1_info['raw_bytes'] == file2_info['raw_bytes']:
        print("  ✓ Files are IDENTICAL at binary level")
        return
    else:
        print("  ✗ Files DIFFER at binary level")
    
    # Text content comparison (normalized line endings)
    print(f"\nNormalized text comparison:")
    if file1_info['text_content'].replace('\r\n', '\n').replace('\r', '\n') == \
       file2_info['text_content'].replace('\r\n', '\n').replace('\r', '\n'):
        print("  ✓ Files are IDENTICAL when line endings are normalized")
        print("  → Difference is only in line ending format")
    else:
        print("  ✗ Files DIFFER even with normalized line endings")
        print("  → Files have actual content differences")
    
    # Line-by-line diff
    print(f"\nLine-by-line unified diff:")
    diff = list(difflib.unified_diff(
        file1_info['lines_normalized'],
        file2_info['lines_normalized'],
        fromfile=f"a/{os.path.basename(file1_path)}",
        tofile=f"b/{os.path.basename(file2_path)}",
        lineterm=''
    ))
    
    if not diff:
        print("  No differences found in content")
    else:
        for line in diff:
            print(f"  {line}")
    
    # Character-by-character analysis if files are small
    if file1_info['file_size'] < 1000 and file2_info['file_size'] < 1000:
        print(f"\nCharacter-by-character analysis:")
        content1 = file1_info['text_content']
        content2 = file2_info['text_content']
        
        min_len = min(len(content1), len(content2))
        for i in range(min_len):
            if content1[i] != content2[i]:
                print(f"  First difference at position {i}:")
                print(f"    Clear payload: {repr(content1[i])} (ord: {ord(content1[i])})")
                print(f"    Unencrypted payload: {repr(content2[i])} (ord: {ord(content2[i])})")
                break
        
        if len(content1) != len(content2):
            print(f"  Length difference: Clear payload has {len(content1)} chars, Unencrypted payload has {len(content2)} chars")

if __name__ == "__main__":

    compare_files(CLEAR_PAYLOAD_FILE, UNENCRYPTED_PAYLOAD_FILE)