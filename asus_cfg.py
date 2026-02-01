#!/usr/bin/env python3
"""
ASUS Router Configuration Backup Tool

Decrypt and encrypt ASUS router configuration backup files (.CFG).
Supports Asuswrt and Asuswrt-Merlin firmware (tested on 388.x series).

Algorithm (reverse-engineered from RT-AX82U firmware):
    - HDR1: Unencrypted NVRAM dump
    - HDR2: XOR-obfuscated with random seed at byte 7
    - Decrypt: (0xFF + rand - encrypted_byte) & 0xFF
    - Encrypt: (0xFF + rand - plaintext_byte) & 0xFF (same operation)

Author: Based on firmware analysis of RT-AX82U 388.25101
License: MIT
"""

import argparse
import sys
import os
from typing import Optional, List, Tuple

__version__ = "1.0.0"

# Header constants
HDR1 = b"HDR1"  # Unencrypted format
HDR2 = b"HDR2"  # Encrypted/obfuscated format

# Metadata bytes (positions 4-7)
# Byte 7 contains the random seed for XOR operation
HEADER_SIZE = 8
RAND_SEED_OFFSET = 7

# Delimiter range (bytes 0x00-0x05 separate NVRAM entries)
DELIMITER_MAX = 0x05


class ASUSConfigError(Exception):
    """Exception raised for ASUS config file errors."""
    pass


def decrypt_byte(encrypted: int, rand_seed: int) -> int:
    """
    Decrypt a single byte using the ASUS XOR algorithm.

    Args:
        encrypted: The encrypted byte value (0-255)
        rand_seed: The random seed from the file header

    Returns:
        Decrypted byte value (0-255)
    """
    return (0xFF + rand_seed - encrypted) & 0xFF


def encrypt_byte(plaintext: int, rand_seed: int) -> int:
    """
    Encrypt a single byte using the ASUS XOR algorithm.
    Note: The algorithm is symmetric, so encryption = decryption.

    Args:
        plaintext: The plaintext byte value (0-255)
        rand_seed: The random seed to use

    Returns:
        Encrypted byte value (0-255)
    """
    return (0xFF + rand_seed - plaintext) & 0xFF


def decrypt_data(encrypted_data: bytes, rand_seed: int) -> bytes:
    """
    Decrypt a byte sequence using the ASUS XOR algorithm.

    Args:
        encrypted_data: The encrypted byte sequence
        rand_seed: The random seed from the file header

    Returns:
        Decrypted byte sequence
    """
    return bytes(decrypt_byte(b, rand_seed) for b in encrypted_data)


def encrypt_data(plaintext_data: bytes, rand_seed: int) -> bytes:
    """
    Encrypt a byte sequence using the ASUS XOR algorithm.

    Args:
        plaintext_data: The plaintext byte sequence
        rand_seed: The random seed to use

    Returns:
        Encrypted byte sequence
    """
    return bytes(encrypt_byte(b, rand_seed) for b in plaintext_data)


def parse_nvram_entries(decrypted_data: bytes) -> List[Tuple[str, str]]:
    """
    Parse decrypted data into NVRAM key-value pairs.

    Entries are separated by delimiter bytes (0x00-0x05).
    Each entry is in the format: key=value

    Args:
        decrypted_data: Decrypted byte sequence

    Returns:
        List of (key, value) tuples
    """
    entries = []
    current = bytearray()

    for byte in decrypted_data:
        if byte <= DELIMITER_MAX:
            if current:
                try:
                    entry_str = bytes(current).decode('utf-8', errors='replace')
                    if '=' in entry_str:
                        key, _, value = entry_str.partition('=')
                        entries.append((key, value))
                except Exception:
                    pass
                current = bytearray()
        else:
            current.append(byte)

    # Handle last entry if no trailing delimiter
    if current:
        try:
            entry_str = bytes(current).decode('utf-8', errors='replace')
            if '=' in entry_str:
                key, _, value = entry_str.partition('=')
                entries.append((key, value))
        except Exception:
            pass

    return entries


def entries_to_bytes(entries: List[Tuple[str, str]], delimiter: int = 0x00) -> bytes:
    """
    Convert NVRAM entries back to byte format.

    Args:
        entries: List of (key, value) tuples
        delimiter: Delimiter byte to use between entries

    Returns:
        Byte sequence ready for encryption
    """
    result = bytearray()
    for key, value in entries:
        entry = f"{key}={value}".encode('utf-8')
        result.extend(entry)
        result.append(delimiter)
    return bytes(result)


def read_cfg_file(filepath: str) -> Tuple[bytes, int, bytes]:
    """
    Read and parse an ASUS .CFG backup file.

    Args:
        filepath: Path to the .CFG file

    Returns:
        Tuple of (header, rand_seed, encrypted_data)

    Raises:
        ASUSConfigError: If file format is invalid
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    if len(data) < HEADER_SIZE:
        raise ASUSConfigError(f"File too small: {len(data)} bytes")

    header = data[:4]

    if header == HDR1:
        # Unencrypted format - no rand seed needed
        return header, 0, data[4:]
    elif header == HDR2:
        # Encrypted format - extract rand seed
        rand_seed = data[RAND_SEED_OFFSET]
        return header, rand_seed, data[HEADER_SIZE:]
    else:
        raise ASUSConfigError(f"Unknown header: {header.hex()} ({header})")


def write_cfg_file(filepath: str, header: bytes, rand_seed: int, data: bytes):
    """
    Write data to an ASUS .CFG backup file.

    Args:
        filepath: Output file path
        header: HDR1 or HDR2
        rand_seed: Random seed (used for HDR2)
        data: Data to write (encrypted for HDR2, plain for HDR1)
    """
    with open(filepath, 'wb') as f:
        f.write(header)
        if header == HDR2:
            # Write metadata bytes (4-7), with rand_seed at position 7
            metadata = bytes([0x00, 0x30, 0x01, rand_seed])
            f.write(metadata)
        f.write(data)


def decrypt_cfg(input_path: str, output_path: Optional[str] = None,
                show_passwords: bool = False, raw_output: bool = False) -> List[Tuple[str, str]]:
    """
    Decrypt an ASUS .CFG backup file.

    Args:
        input_path: Path to encrypted .CFG file
        output_path: Optional output file path
        show_passwords: If False, redact sensitive values
        raw_output: If True, output raw decrypted bytes instead of parsed entries

    Returns:
        List of (key, value) tuples
    """
    header, rand_seed, encrypted_data = read_cfg_file(input_path)

    if header == HDR1:
        print(f"[*] HDR1 format (unencrypted)")
        decrypted = encrypted_data
    else:
        print(f"[*] HDR2 format (encrypted)")
        print(f"[*] Random seed: 0x{rand_seed:02X}")
        decrypted = decrypt_data(encrypted_data, rand_seed)

    if raw_output:
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            print(f"[+] Raw decrypted data written to: {output_path}")
        return []

    entries = parse_nvram_entries(decrypted)
    print(f"[+] Parsed {len(entries)} NVRAM entries")

    # Sensitive field patterns to redact
    sensitive_patterns = [
        'passwd', 'password', 'psk', 'key', 'secret',
        'token', 'crt', 'cert', 'private', 'wpa'
    ]

    output_lines = []
    for key, value in entries:
        display_value = value
        if not show_passwords:
            key_lower = key.lower()
            if any(pattern in key_lower for pattern in sensitive_patterns):
                if value:  # Only redact non-empty values
                    display_value = "<REDACTED>"
        output_lines.append(f"{key}={display_value}")

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(output_lines))
        print(f"[+] Decrypted config written to: {output_path}")

    return entries


def encrypt_cfg(input_path: str, output_path: str, rand_seed: Optional[int] = None):
    """
    Encrypt a plaintext NVRAM dump to ASUS .CFG format.

    Args:
        input_path: Path to plaintext file (key=value per line)
        output_path: Output .CFG file path
        rand_seed: Random seed to use (0-255), random if not specified
    """
    # Read plaintext entries
    entries = []
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, _, value = line.partition('=')
                entries.append((key, value))

    print(f"[*] Read {len(entries)} entries from {input_path}")

    # Generate random seed if not provided
    if rand_seed is None:
        rand_seed = int.from_bytes(os.urandom(1), 'big')
    rand_seed = rand_seed & 0xFF  # Ensure 0-255

    print(f"[*] Using random seed: 0x{rand_seed:02X}")

    # Convert entries to bytes
    plaintext = entries_to_bytes(entries)

    # Encrypt
    encrypted = encrypt_data(plaintext, rand_seed)

    # Write output
    write_cfg_file(output_path, HDR2, rand_seed, encrypted)
    print(f"[+] Encrypted config written to: {output_path}")


def print_summary(entries: List[Tuple[str, str]]):
    """Print a summary of interesting configuration values."""
    interesting_keys = {
        'productid': 'Model',
        'lan_ipaddr': 'LAN IP',
        'lan_hwaddr': 'LAN MAC',
        'wan_ipaddr': 'WAN IP',
        'wan_hwaddr': 'WAN MAC',
        'wl0_ssid': '2.4GHz SSID',
        'wl1_ssid': '5GHz SSID',
        'http_username': 'Admin User',
        'time_zone': 'Timezone',
        'firmver': 'Firmware',
        'buildno': 'Build',
    }

    print("\n" + "=" * 50)
    print("Configuration Summary")
    print("=" * 50)

    entry_dict = dict(entries)
    for key, label in interesting_keys.items():
        if key in entry_dict:
            print(f"  {label}: {entry_dict[key]}")


def main():
    parser = argparse.ArgumentParser(
        description="ASUS Router Configuration Backup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Decrypt a backup file:
    %(prog)s decrypt Settings_RT-AX82U.CFG -o decrypted.txt

  Decrypt showing passwords:
    %(prog)s decrypt Settings_RT-AX82U.CFG -o decrypted.txt --show-passwords

  Encrypt a plaintext config:
    %(prog)s encrypt decrypted.txt -o NewSettings.CFG

  Show summary only:
    %(prog)s decrypt Settings_RT-AX82U.CFG --summary

Supported formats:
  - HDR1: Unencrypted NVRAM dump
  - HDR2: XOR-obfuscated (Asuswrt-Merlin 388.x)

Project: https://github.com/FancyWaifu/asus-cfg-tool
        """
    )

    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a .CFG backup file')
    decrypt_parser.add_argument('input', help='Input .CFG file')
    decrypt_parser.add_argument('-o', '--output', help='Output file (default: stdout preview)')
    decrypt_parser.add_argument('--show-passwords', action='store_true',
                                help='Show passwords instead of redacting')
    decrypt_parser.add_argument('--raw', action='store_true',
                                help='Output raw decrypted bytes')
    decrypt_parser.add_argument('--summary', action='store_true',
                                help='Show configuration summary')

    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a plaintext config file')
    encrypt_parser.add_argument('input', help='Input plaintext file (key=value per line)')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Output .CFG file')
    encrypt_parser.add_argument('--seed', type=int, help='Random seed (0-255, default: random)')

    # Info subcommand
    info_parser = subparsers.add_parser('info', help='Show file information')
    info_parser.add_argument('input', help='Input .CFG file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == 'decrypt':
            entries = decrypt_cfg(
                args.input,
                args.output,
                show_passwords=args.show_passwords,
                raw_output=args.raw
            )

            if args.summary and entries:
                print_summary(entries)
            elif not args.output and not args.raw:
                # Preview first 30 entries
                print("\n" + "=" * 50)
                print("Preview (first 30 entries)")
                print("=" * 50)
                for key, value in entries[:30]:
                    if len(value) > 60:
                        value = value[:60] + "..."
                    print(f"  {key}={value}")
                if len(entries) > 30:
                    print(f"  ... and {len(entries) - 30} more entries")
                print("\nUse -o <file> to save all entries")

        elif args.command == 'encrypt':
            encrypt_cfg(args.input, args.output, args.seed)

        elif args.command == 'info':
            header, rand_seed, data = read_cfg_file(args.input)
            print(f"File: {args.input}")
            print(f"Size: {os.path.getsize(args.input)} bytes")
            print(f"Header: {header.decode('ascii')} ({header.hex()})")
            if header == HDR2:
                print(f"Random Seed: 0x{rand_seed:02X} ({rand_seed})")
                print(f"Encrypted Data: {len(data)} bytes")
            else:
                print(f"Data: {len(data)} bytes (unencrypted)")

    except ASUSConfigError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[!] File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
