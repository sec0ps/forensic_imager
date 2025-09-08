# Forensic Tools Suite

A Python-based suite for digital forensics operations including drive imaging and data recovery with chain of custody support.

## Tools Included

### 1. Forensic Drive Imaging Tool (`forensic_imager.py`)
Professional-grade disk imaging tool for creating forensically sound copies of storage devices.

### 2. Forensic Data Recovery Tool (`forensic_recovery.py`) 
GUI-based data recovery tool for extracting deleted files and recovering data from damaged filesystems.

## Features

### Drive Imaging Tool
- **Automated dependency installation** - Installs required tools (ddrescue, pv, etc.)
- **Multiple imaging methods** with progress monitoring:
  - DD with PV - Standard imaging with real-time progress
  - DDrescue with PV - Recovery imaging for damaged drives
- **SHA-256 integrity verification** - Automatic checksum validation
- **Professional documentation** - Generates standardized forensic logs
- **Enhanced safety checks** - Prevents data loss with verification steps
- **Smart unmounting** - Automatically handles mounted filesystems

### Data Recovery Tool
- **Multiple recovery engines** - Uses foremost, scalpel, and other tools
- **GUI interface** - User-friendly tkinter-based interface
- **Dual view modes** - Table and tree organization of recovered files
- **File type detection** - Automatic classification of recovered data
- **Search capabilities** - Find files by name or content
- **SHA-256 verification** - Hash verification of recovered files
- **Professional logging** - Complete audit trail with metadata preservation

## Requirements

### System Requirements
- Linux operating system (Ubuntu/Debian preferred)
- Root/sudo privileges
- Python 3.6 or higher
- Available USB ports for external drives

### Dependencies
Both tools automatically install required dependencies:
- **testdisk** (includes photorec)
- **foremost** (primary recovery engine)
- **file** (MIME type detection)
- **pv** (progress monitoring)
- **poppler-utils** (PDF metadata)
- **libimage-exiftool-perl** (image metadata)
- **python3-tk** (GUI framework)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd forensic-tools

# Make scripts executable
chmod +x forensic_imager.py
chmod +x forensic_recovery.py
```

## Usage

### Drive Imaging
```bash
# Run with root privileges (required)
sudo python3 forensic_imager.py
```

**Workflow:**
1. **Dependency check** - Automatically installs missing tools
2. **Case information** - Enter operator details and case number
3. **Device selection** - Choose source and destination drives
4. **Safety verification** - Automatic capacity and mount checks
5. **Imaging method** - Select DD or DDrescue (both include progress monitoring)
6. **Confirmation** - Final verification before imaging begins
7. **Imaging process** - Real-time progress with pv monitoring
8. **Integrity verification** - SHA-256 checksum comparison
9. **Documentation** - Professional log generation

### Data Recovery
```bash
# Run with root privileges (recommended)
sudo python3 forensic_recovery.py
```

**Workflow:**
1. **Source selection** - Choose device or image file
2. **Scan for files** - Automated recovery using foremost/scalpel
3. **File browsing** - View recovered files in table or tree format
4. **Search and filter** - Find specific files or content
5. **Selection** - Choose files for recovery
6. **Recovery process** - Copy files with hash verification
7. **Documentation** - JSON log with complete metadata

## Output Files

### Drive Imaging
- **imaging_log_YYYYMMDD_HHMMSS.txt** - Official forensic documentation
- **Checksum verification** - SHA-256 hash comparison results
- **Error logs** - Complete audit trail of operations

### Data Recovery
- **recovery_DEVICE_TIMESTAMP/** - Recovered files directory
- **recovery_log.json** - Detailed recovery documentation with metadata
- **Operation logs** - Complete session history

## Professional Features

### Legal Compliance
- **Chain of custody** documentation templates
- **Standardized logging** formats for court admissibility
- **Integrity verification** with cryptographic hashing
- **Comprehensive audit trails** for all operations

### Safety Features
- **Write-blocking behavior** - Read-only recovery operations
- **Multiple confirmations** - Prevents accidental data loss
- **Automatic unmounting** - Handles mounted filesystems safely
- **Capacity verification** - Ensures adequate destination space

## Use Cases

- **Digital forensics investigations**
- **Evidence preservation and analysis**
- **Data recovery operations**
- **System backup and migration**
- **Incident response activities**
- **Computer forensics training**

## Important Notes

### Legal Requirements
- Obtain proper authorization before imaging any device
- Maintain chain of custody documentation
- Comply with applicable laws and regulations
- Document all forensic procedures thoroughly

### Technical Considerations
- **USB 3.0 recommended** for faster transfer speeds
- **Large operations** can take several hours
- **Verify checksums** before considering imaging complete
- **Use write-blockers** for evidence preservation when possible

## Troubleshooting

### Common Issues
- **Permission errors** - Ensure running with sudo privileges
- **Device not found** - Check USB connections and device recognition
- **Slow performance** - Use USB 3.0 ports and high-speed devices
- **Mount conflicts** - Tools automatically handle unmounting

### Getting Help
- Check log files for detailed error information
- Verify all dependencies are properly installed
- Ensure adequate free space for recovery operations
- Review device compatibility and connection status

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
