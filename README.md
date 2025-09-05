# Forensic Drive Imaging Tool

A comprehensive Python script for creating forensic images of hard drives with integrity verification and professional documentation.

## Features

- **Automated Setup**: Installs required dependencies (ddrescue, pv, forensic tools)
- **Interactive Device Selection**: Safe drive selection with capacity verification
- **Multiple Imaging Methods**: dd, ddrescue, dd+pv with progress monitoring
- **SHA-256 Verification**: Automatic integrity checking with checksum comparison
- **Professional Documentation**: Generates standardized imaging logs for legal compliance
- **Safety Checks**: Prevents accidental data loss with multiple confirmations

## Requirements

- Linux operating system
- Root/sudo privileges
- Python 3.6+
- Available USB ports for source and destination drives

## Quick Start

```bash
# Clone and run
git clone <repository-url>
cd forensic-drive-imaging
chmod +x forensic_imager.py
sudo python3 forensic_imager.py
```

## Usage

1. **Run with root privileges** - Required for low-level drive access
2. **Connect drives** - Source drive to image and destination drive
3. **Follow prompts** - Script guides through device selection and method choice
4. **Wait for completion** - Imaging can take several hours for large drives
5. **Review documentation** - Professional log generated automatically

## Output Files

- **imaging_log_YYYYMMDD_HHMMSS.txt** - Official forensic documentation
- **Checksum files** - SHA-256 verification records
- **Recovery logs** - DDrescue operation details (if applicable)

## Legal Notice

⚠️ **IMPORTANT**: This tool is for authorized forensic investigations only. Ensure proper legal authorization before imaging any storage device. Users are responsible for compliance with applicable laws and regulations.

## Contact
For professional forensic services, tool integrations, or technical support contact: operations@redcellsecurity.org

## License
**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support My Work
If you find this forensic imaging tool useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
