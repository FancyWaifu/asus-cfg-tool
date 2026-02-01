# ASUS Router Configuration Backup Tool

Decrypt and encrypt ASUS router configuration backup files (`.CFG`).

Tested on **Asuswrt-Merlin 388.x** firmware (RT-AX82U, RT-AX86U, and similar models).

## Features

- **Decrypt** `.CFG` backup files to readable plaintext
- **Encrypt** plaintext configs back to `.CFG` format
- **Automatic password redaction** (optional)
- **No dependencies** - pure Python 3
- Supports both **HDR1** (unencrypted) and **HDR2** (obfuscated) formats

## Installation

```bash
# Clone the repository
git clone https://github.com/FancyWaifu/asus-cfg-tool.git
cd asus-cfg-tool

# Make executable (optional)
chmod +x asus_cfg.py
```

**Requirements:** Python 3.6+

## Usage

### Decrypt a Backup File

```bash
# Decrypt to file (passwords redacted)
python3 asus_cfg.py decrypt Settings_RT-AX82U.CFG -o decrypted.txt

# Decrypt with passwords visible
python3 asus_cfg.py decrypt Settings_RT-AX82U.CFG -o decrypted.txt --show-passwords

# Preview only (no output file)
python3 asus_cfg.py decrypt Settings_RT-AX82U.CFG

# Show configuration summary
python3 asus_cfg.py decrypt Settings_RT-AX82U.CFG --summary
```

### Encrypt a Config File

```bash
# Encrypt plaintext back to .CFG format
python3 asus_cfg.py encrypt decrypted.txt -o NewSettings.CFG

# Use specific random seed
python3 asus_cfg.py encrypt decrypted.txt -o NewSettings.CFG --seed 42
```

### Show File Information

```bash
python3 asus_cfg.py info Settings_RT-AX82U.CFG
```

Output:
```
File: Settings_RT-AX82U.CFG
Size: 77832 bytes
Header: HDR2 (48445232)
Random Seed: 0x03 (3)
Encrypted Data: 77824 bytes
```

## File Formats

### HDR1 (Unencrypted)
- Header: `HDR1` (4 bytes)
- Data: Raw NVRAM dump

### HDR2 (Obfuscated)
- Header: `HDR2` (4 bytes)
- Metadata: 4 bytes (byte 7 = random seed)
- Data: XOR-obfuscated NVRAM dump

## Technical Details

### Encryption Algorithm

The "encryption" is actually XOR obfuscation:

```python
# Decrypt (and encrypt - same operation)
decrypted_byte = (0xFF + rand_seed - encrypted_byte) & 0xFF
```

Where `rand_seed` is stored at byte offset 7 in the file.

### NVRAM Entry Format

Entries are separated by delimiter bytes (0x00-0x05):
```
key1=value1<delimiter>key2=value2<delimiter>...
```

### Reverse Engineering Source

Algorithm discovered through static analysis of `libshared.so` from RT-AX82U firmware 3.0.0.4.388_25101:
- Encryption functions at offset 0x72158
- XOR obfuscation with position-independent random seed

## Tested Firmware

| Model | Firmware | Status |
|-------|----------|--------|
| RT-AX82U | 388.24963 (Merlin) | ✅ Working |
| RT-AX82U | 388.25101 (Merlin) | ✅ Working |
| RT-AX86U | 388.x (Merlin) | Should work |
| RT-AX58U | 388.x (Merlin) | Should work |

## Example Output

```
$ python3 asus_cfg.py decrypt Settings_RT-AX82U.CFG --summary

[*] HDR2 format (encrypted)
[*] Random seed: 0x03
[+] Parsed 3479 NVRAM entries

==================================================
Configuration Summary
==================================================
  Model: RT-AX82U
  LAN IP: 192.168.50.1
  LAN MAC: 08:BF:B8:8E:68:28
  WAN IP: 173.24.73.213
  2.4GHz SSID: MyNetwork
  5GHz SSID: MyNetwork_5G
  Admin User: admin
```

## Security Notes

1. **This is obfuscation, not encryption** - The algorithm provides no real security
2. **Passwords are stored in the backup** - Handle decrypted files carefully
3. **Same algorithm for all routers** - Any HDR2 file can be decrypted without device-specific keys

## Related Projects

- [WrtSettings](https://github.com/medo64/WrtSettings) - Windows GUI tool
- [Asus-Router-Config-Decoder](https://github.com/VladDBA/Asus-Router-Config-Decoder) - PowerShell decoder
- [Asuswrt-Merlin](https://github.com/RMerl/asuswrt-merlin.ng) - Custom firmware source

## License

MIT License - See [LICENSE](LICENSE) file

## Disclaimer

This tool is for educational and personal use. Only use it on your own devices and backups. The author is not responsible for any misuse.
