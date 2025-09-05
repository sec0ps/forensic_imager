#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Forensic Drive Imaging Module
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This module provides comprehensive forensic drive imaging capabilities
#          for digital forensics investigations, evidence preservation, and
#          system backup operations. It automates the process of creating
#          bit-for-bit copies of storage devices using industry-standard tools
#          and follows established forensic procedures with integrity verification.
#
# Features:
#          - Automated dependency installation (ddrescue, pv, forensic tools)
#          - Interactive device selection with safety checks
#          - Multiple imaging methods (dd, ddrescue, dd+pv)
#          - SHA-256 integrity verification
#          - Professional documentation and logging
#          - Chain of custody documentation templates
#          - Comprehensive error tracking and reporting
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This toolkit is intended for authorized forensic investigations and
#         security testing only. Users are responsible for ensuring compliance
#         with all applicable laws and regulations regarding data acquisition,
#         chain of custody, and evidence handling. Unauthorized imaging of
#         storage devices may violate local, state, federal, and international laws.
#
# FORENSIC COMPLIANCE: This tool is designed to support forensic best practices
#                      including write-blocking, integrity verification, and
#                      comprehensive documentation. Users must ensure proper
#                      legal authorization before imaging any storage device.
#
# =============================================================================

import os
import sys
import subprocess
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
import shutil

class ForensicImager:
    def __init__(self):
        self.log_entries = []
        self.case_info = {}
        self.source_device = None
        self.destination_device = None
        self.imaging_method = None
        self.command_used = None
        self.start_time = None
        self.end_time = None
        self.duration = None
        self.source_checksum = None
        self.dest_checksum = None
        self.checksums_match = False
        self.errors_anomalies = []

    def log(self, message, level="INFO"):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        print(log_entry)
        self.log_entries.append(log_entry)

        # Track errors and anomalies for the final report
        if level in ["ERROR", "WARNING"]:
            self.errors_anomalies.append(f"{level}: {message}")

    def check_root_privileges(self):
        """Check if script is running with root privileges"""
        if os.geteuid() != 0:
            self.log("ERROR: This script requires root privileges for drive operations", "ERROR")
            self.log("Please run with: sudo python3 forensic_imager.py", "ERROR")
            sys.exit(1)
        self.log("Root privileges confirmed")

    def install_dependencies(self):
        """Install required packages for forensic imaging"""
        self.log("Checking and installing required dependencies...")

        # Detect distribution
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read()

            if 'debian' in os_info.lower() or 'ubuntu' in os_info.lower():
                package_manager = 'apt'
                packages = ['gddrescue', 'pv', 'util-linux', 'coreutils']
                update_cmd = ['apt', 'update']
                install_cmd = ['apt', 'install', '-y'] + packages

            elif 'fedora' in os_info.lower() or 'rhel' in os_info.lower() or 'centos' in os_info.lower():
                package_manager = 'dnf'
                packages = ['ddrescue', 'pv', 'util-linux', 'coreutils']
                update_cmd = ['dnf', 'check-update']
                install_cmd = ['dnf', 'install', '-y'] + packages

            else:
                self.log("Unsupported distribution. Please install gddrescue, pv manually", "WARNING")
                return

        except FileNotFoundError:
            self.log("Could not detect distribution", "WARNING")
            return

        # Update package lists
        try:
            self.log(f"Updating package lists using {package_manager}...")
            subprocess.run(update_cmd, check=False, capture_output=True)
        except Exception as e:
            self.log(f"Warning: Could not update package lists: {e}", "WARNING")

        # Install packages
        try:
            self.log(f"Installing packages: {', '.join(packages)}")
            result = subprocess.run(install_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.log("Dependencies installed successfully")
            else:
                self.log(f"Warning: Some packages may not have installed: {result.stderr}", "WARNING")
        except Exception as e:
            self.log(f"Error installing dependencies: {e}", "ERROR")

    def get_block_devices(self):
        """Get list of available block devices"""
        try:
            result = subprocess.run(['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,MODEL'],
                                  capture_output=True, text=True, check=True)
            devices_json = json.loads(result.stdout)

            # Filter for disk devices (not partitions)
            disks = []
            for device in devices_json['blockdevices']:
                if device['type'] == 'disk':
                    # Get additional info
                    device_path = f"/dev/{device['name']}"
                    try:
                        # Get serial number if available
                        serial_result = subprocess.run(['udevadm', 'info', '--query=all', '--name=' + device_path],
                                                     capture_output=True, text=True)
                        serial = "Unknown"
                        for line in serial_result.stdout.split('\n'):
                            if 'ID_SERIAL_SHORT' in line:
                                serial = line.split('=')[1]
                                break
                    except:
                        serial = "Unknown"

                    # Get capacity in bytes for accurate size reporting
                    try:
                        capacity_result = subprocess.run(['blockdev', '--getsize64', device_path],
                                                       capture_output=True, text=True, check=True)
                        capacity_bytes = int(capacity_result.stdout.strip())
                        capacity_gb = capacity_bytes / (1024**3)
                        capacity_display = f"{capacity_gb:.2f} GB ({capacity_bytes} bytes)"
                    except:
                        capacity_display = device.get('size', 'Unknown')

                    disks.append({
                        'name': device['name'],
                        'path': device_path,
                        'size': device['size'],
                        'capacity': capacity_display,
                        'model': device.get('model', 'Unknown'),
                        'serial': serial,
                        'mountpoint': device.get('mountpoint', 'Not mounted')
                    })

            return disks

        except subprocess.CalledProcessError as e:
            self.log(f"Error getting block devices: {e}", "ERROR")
            return []
        except json.JSONDecodeError as e:
            self.log(f"Error parsing device information: {e}", "ERROR")
            return []

    def display_devices(self, devices):
        """Display available devices for selection"""
        print("\n" + "="*80)
        print("AVAILABLE BLOCK DEVICES")
        print("="*80)
        print(f"{'#':<3} {'Device':<12} {'Size':<10} {'Model':<25} {'Serial':<15} {'Status'}")
        print("-"*80)

        for i, device in enumerate(devices, 1):
            status = "MOUNTED" if device['mountpoint'] != 'Not mounted' else "Available"
            print(f"{i:<3} {device['path']:<12} {device['size']:<10} {device['model'][:24]:<25} "
                  f"{device['serial'][:14]:<15} {status}")
        print("-"*80)

    def select_device(self, devices, device_type):
        """Allow user to select source or destination device"""
        while True:
            try:
                choice = input(f"\nSelect {device_type} device (enter number 1-{len(devices)}): ").strip()

                if not choice:
                    continue

                device_num = int(choice)
                if 1 <= device_num <= len(devices):
                    selected_device = devices[device_num - 1]

                    # Warning for mounted devices
                    if selected_device['mountpoint'] != 'Not mounted':
                        print(f"WARNING: Device {selected_device['path']} is currently mounted!")
                        confirm = input("Continue anyway? (yes/no): ").strip().lower()
                        if confirm not in ['yes', 'y']:
                            continue

                    # Confirmation
                    print(f"\nSelected {device_type}: {selected_device['path']}")
                    print(f"Model: {selected_device['model']}")
                    print(f"Size: {selected_device['size']}")
                    print(f"Serial: {selected_device['serial']}")

                    confirm = input(f"Confirm this as {device_type} device? (yes/no): ").strip().lower()
                    if confirm in ['yes', 'y']:
                        return selected_device
                else:
                    print(f"Please enter a number between 1 and {len(devices)}")

            except ValueError:
                print("Please enter a valid number")
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                sys.exit(0)

    def unmount_device(self, device_path):
        """Unmount all partitions on a device"""
        try:
            self.log(f"Unmounting all partitions on {device_path}")
            result = subprocess.run(['umount', f"{device_path}*"],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"Successfully unmounted {device_path}")
            else:
                # This is often normal (partitions not mounted)
                self.log(f"Unmount result for {device_path}: {result.stderr.strip()}", "INFO")
        except Exception as e:
            self.log(f"Error unmounting {device_path}: {e}", "WARNING")

    def select_imaging_method(self):
        """Allow user to select imaging method"""
        methods = {
            '1': 'dd - Standard method for healthy drives',
            '2': 'ddrescue - Recovery method for damaged drives',
            '3': 'dd with pv - Standard method with enhanced progress monitoring'
        }

        print("\n" + "="*50)
        print("SELECT IMAGING METHOD")
        print("="*50)
        for key, value in methods.items():
            print(f"{key}. {value}")
        print("-"*50)

        while True:
            try:
                choice = input("Select imaging method (1-3): ").strip()
                if choice in methods:
                    method_name = methods[choice].split(' - ')[0]
                    print(f"Selected method: {methods[choice]}")
                    confirm = input("Confirm selection? (yes/no): ").strip().lower()
                    if confirm in ['yes', 'y']:
                        return choice, method_name
                else:
                    print("Please enter 1, 2, or 3")
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                sys.exit(0)

    def get_case_information(self):
        """Collect case information for documentation"""
        print("\n" + "="*50)
        print("CASE INFORMATION")
        print("="*50)

        self.case_info = {
            'operator': input("Operator name: ").strip(),
            'case_number': input("Case/Ticket number: ").strip(),
            'description': input("Case description: ").strip(),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def create_image_dd(self, output_path=None):
        """Create image using dd method"""
        if output_path is None:
            output_path = self.destination_device['path']

        cmd = [
            'dd',
            f"if={self.source_device['path']}",
            f"of={output_path}",
            'bs=64K',
            'status=progress',
            'conv=noerror,sync'
        ]

        self.command_used = ' '.join(cmd)
        self.log(f"Starting DD imaging: {self.command_used}")
        self.log("This may take several hours depending on drive size...")

        self.start_time = datetime.now()
        start_time_epoch = time.time()
        try:
            result = subprocess.run(cmd, check=True)
            end_time_epoch = time.time()
            self.end_time = datetime.now()
            self.duration = end_time_epoch - start_time_epoch
            self.log(f"DD imaging completed successfully in {self.duration:.2f} seconds")
            return True
        except subprocess.CalledProcessError as e:
            self.end_time = datetime.now()
            self.duration = time.time() - start_time_epoch
            self.log(f"DD imaging failed: {e}", "ERROR")
            return False

    def create_image_ddrescue(self, output_path=None, log_path=None):
        """Create image using ddrescue method"""
        if output_path is None:
            output_path = self.destination_device['path']
        if log_path is None:
            log_path = f"/tmp/ddrescue_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        cmd = [
            'ddrescue',
            self.source_device['path'],
            output_path,
            log_path
        ]

        self.command_used = ' '.join(cmd)
        self.log(f"Starting DDrescue imaging: {self.command_used}")
        self.log(f"Recovery log will be saved to: {log_path}")
        self.log("This may take several hours depending on drive condition...")

        self.start_time = datetime.now()
        start_time_epoch = time.time()
        try:
            result = subprocess.run(cmd, check=True)
            end_time_epoch = time.time()
            self.end_time = datetime.now()
            self.duration = end_time_epoch - start_time_epoch
            self.log(f"DDrescue imaging completed successfully in {self.duration:.2f} seconds")
            self.log(f"Recovery log saved to: {log_path}")
            return True
        except subprocess.CalledProcessError as e:
            self.end_time = datetime.now()
            self.duration = time.time() - start_time_epoch
            self.log(f"DDrescue imaging failed: {e}", "ERROR")
            return False

    def create_image_dd_pv(self, output_path=None):
        """Create image using dd with pv for progress monitoring"""
        if output_path is None:
            output_path = self.destination_device['path']

        # Use shell pipeline for pv | dd
        cmd = f"pv {self.source_device['path']} | dd of={output_path} bs=64K conv=noerror,sync"

        self.command_used = cmd
        self.log(f"Starting DD+PV imaging: {cmd}")
        self.log("This may take several hours depending on drive size...")

        self.start_time = datetime.now()
        start_time_epoch = time.time()
        try:
            result = subprocess.run(cmd, shell=True, check=True)
            end_time_epoch = time.time()
            self.end_time = datetime.now()
            self.duration = end_time_epoch - start_time_epoch
            self.log(f"DD+PV imaging completed successfully in {self.duration:.2f} seconds")
            return True
        except subprocess.CalledProcessError as e:
            self.end_time = datetime.now()
            self.duration = time.time() - start_time_epoch
            self.log(f"DD+PV imaging failed: {e}", "ERROR")
            return False

    def calculate_checksum(self, device_path, algorithm='sha256'):
        """Calculate checksum for verification"""
        self.log(f"Calculating {algorithm.upper()} checksum for {device_path}")
        self.log("This may take considerable time for large drives...")

        try:
            if algorithm == 'md5':
                cmd = ['md5sum', device_path]
            elif algorithm == 'sha256':
                cmd = ['sha256sum', device_path]
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            checksum = result.stdout.split()[0]
            self.log(f"{algorithm.upper()} checksum for {device_path}: {checksum}")
            return checksum

        except subprocess.CalledProcessError as e:
            self.log(f"Error calculating checksum: {e}", "ERROR")
            return None

    def verify_image_integrity(self):
        """Verify image integrity by comparing checksums"""
        self.log("Starting image integrity verification...")

        # Calculate checksums for both source and destination
        self.source_checksum = self.calculate_checksum(self.source_device['path'], 'sha256')
        self.dest_checksum = self.calculate_checksum(self.destination_device['path'], 'sha256')

        if self.source_checksum and self.dest_checksum:
            if self.source_checksum == self.dest_checksum:
                self.checksums_match = True
                self.log("SUCCESS: Image integrity verified - checksums match!", "SUCCESS")
                return True
            else:
                self.checksums_match = False
                self.log("ERROR: Image integrity check FAILED - checksums do not match!", "ERROR")
                self.log(f"Source SHA256: {self.source_checksum}", "ERROR")
                self.log(f"Destination SHA256: {self.dest_checksum}", "ERROR")
                return False
        else:
            self.checksums_match = False
            self.log("ERROR: Could not verify image integrity due to checksum calculation failure", "ERROR")
            return False

    def format_duration(self, duration_seconds):
        """Format duration in seconds to human readable format"""
        if duration_seconds is None:
            return "Unknown"

        hours = int(duration_seconds // 3600)
        minutes = int((duration_seconds % 3600) // 60)
        seconds = int(duration_seconds % 60)

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    def generate_imaging_log(self):
        """Generate official imaging log using the standardized template"""
        log_filename = f"imaging_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        try:
            with open(log_filename, 'w') as f:
                f.write("DRIVE IMAGING LOG\n")
                f.write("=" * 50 + "\n")
                f.write(f"Date/Time Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'Not recorded'}\n")
                f.write(f"Operator: {self.case_info.get('operator', 'Not specified')}\n")
                f.write(f"Case/Ticket Number: {self.case_info.get('case_number', 'Not specified')}\n\n")

                f.write("SOURCE DRIVE:\n")
                if self.source_device:
                    f.write(f"- Device: {self.source_device['path']}\n")
                    f.write(f"- Make/Model: {self.source_device['model']}\n")
                    f.write(f"- Serial Number: {self.source_device['serial']}\n")
                    f.write(f"- Capacity: {self.source_device['capacity']}\n\n")
                else:
                    f.write("- Device: Not recorded\n")
                    f.write("- Make/Model: Not recorded\n")
                    f.write("- Serial Number: Not recorded\n")
                    f.write("- Capacity: Not recorded\n\n")

                f.write("DESTINATION DRIVE:\n")
                if self.destination_device:
                    f.write(f"- Device: {self.destination_device['path']}\n")
                    f.write(f"- Make/Model: {self.destination_device['model']}\n")
                    f.write(f"- Serial Number: {self.destination_device['serial']}\n")
                    f.write(f"- Capacity: {self.destination_device['capacity']}\n\n")
                else:
                    f.write("- Device: Not recorded\n")
                    f.write("- Make/Model: Not recorded\n")
                    f.write("- Serial Number: Not recorded\n")
                    f.write("- Capacity: Not recorded\n\n")

                # Imaging method with checkboxes
                f.write("IMAGING METHOD:\n")
                dd_check = "[X]" if self.imaging_method == "dd" else "[ ]"
                ddrescue_check = "[X]" if self.imaging_method == "ddrescue" else "[ ]"
                other_check = "[X]" if self.imaging_method not in ["dd", "ddrescue"] else "[ ]"
                other_method = self.imaging_method if self.imaging_method not in ["dd", "ddrescue"] else ""

                f.write(f"{dd_check} DD  {ddrescue_check} DDrescue  {other_check} Other: {other_method}\n\n")

                f.write(f"COMMAND USED: {self.command_used or 'Not recorded'}\n")
                f.write(f"START TIME: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'Not recorded'}\n")
                f.write(f"END TIME: {self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'Not recorded'}\n")
                f.write(f"TOTAL DURATION: {self.format_duration(self.duration)}\n\n")

                f.write("VERIFICATION:\n")
                f.write(f"- Source SHA256: {self.source_checksum or 'Not calculated'}\n")
                f.write(f"- Destination SHA256: {self.dest_checksum or 'Not calculated'}\n")
                yes_check = "[X]" if self.checksums_match else "[ ]"
                no_check = "[ ]" if self.checksums_match else "[X]"
                f.write(f"- Checksums Match: {yes_check} Yes  {no_check} No\n\n")

                f.write("ERRORS/ANOMALIES:\n")
                if self.errors_anomalies:
                    for error in self.errors_anomalies:
                        f.write(f"- {error}\n")
                else:
                    f.write("- None reported\n")
                f.write("\n")

                f.write("OPERATOR SIGNATURE: ________________________________\n\n")

                # Additional detailed log
                f.write("\n" + "=" * 50 + "\n")
                f.write("DETAILED OPERATION LOG\n")
                f.write("=" * 50 + "\n")
                for log_entry in self.log_entries:
                    f.write(f"{log_entry}\n")

            self.log(f"Official imaging log saved to: {log_filename}")
            return log_filename

        except Exception as e:
            self.log(f"Error generating imaging log: {e}", "ERROR")
            return None

    def generate_report(self):
        """Generate comprehensive imaging report (legacy function for compatibility)"""
        return self.generate_imaging_log()

    def run_safety_checks(self):
        """Perform safety checks before imaging"""
        self.log("Performing pre-imaging safety checks...")

        # Check if source and destination are different
        if self.source_device['path'] == self.destination_device['path']:
            self.log("CRITICAL ERROR: Source and destination devices are the same!", "ERROR")
            return False

        # Check destination capacity
        try:
            # Get actual sizes in bytes
            source_size = subprocess.run(['blockdev', '--getsize64', self.source_device['path']],
                                       capture_output=True, text=True, check=True)
            dest_size = subprocess.run(['blockdev', '--getsize64', self.destination_device['path']],
                                     capture_output=True, text=True, check=True)

            source_bytes = int(source_size.stdout.strip())
            dest_bytes = int(dest_size.stdout.strip())

            if dest_bytes < source_bytes:
                self.log("ERROR: Destination drive is smaller than source drive!", "ERROR")
                self.log(f"Source size: {source_bytes} bytes", "ERROR")
                self.log(f"Destination size: {dest_bytes} bytes", "ERROR")
                return False

        except Exception as e:
            self.log(f"Warning: Could not verify drive sizes: {e}", "WARNING")

        self.log("Safety checks passed")
        return True

    def main(self):
        """Main execution flow"""
        print("FORENSIC DRIVE IMAGING TOOL")
        print("=" * 50)

        # Check privileges
        self.check_root_privileges()

        # Install dependencies
        self.install_dependencies()

        # Get case information
        self.get_case_information()

        # Get available devices
        devices = self.get_block_devices()
        if not devices:
            self.log("No block devices found", "ERROR")
            sys.exit(1)

        # Display devices and select source
        self.display_devices(devices)
        self.source_device = self.select_device(devices, "SOURCE")

        # Select destination (excluding source)
        dest_devices = [d for d in devices if d['path'] != self.source_device['path']]
        if not dest_devices:
            self.log("No available destination devices", "ERROR")
            sys.exit(1)

        print(f"\nSource device selected: {self.source_device['path']}")
        print("Available destination devices:")
        self.display_devices(dest_devices)
        self.destination_device = self.select_device(dest_devices, "DESTINATION")

        # Safety checks
        if not self.run_safety_checks():
            self.log("Safety checks failed. Aborting operation.", "ERROR")
            sys.exit(1)

        # Unmount devices
        self.unmount_device(self.source_device['path'])
        self.unmount_device(self.destination_device['path'])

        # Select imaging method
        method_choice, self.imaging_method = self.select_imaging_method()

        # Final confirmation
        print("\n" + "="*60)
        print("FINAL CONFIRMATION")
        print("="*60)
        print(f"Source Device: {self.source_device['path']} ({self.source_device['model']})")
        print(f"Destination Device: {self.destination_device['path']} ({self.destination_device['model']})")
        print(f"Imaging Method: {self.imaging_method}")
        print(f"Case: {self.case_info['case_number']}")
        print("="*60)
        print("WARNING: This will OVERWRITE ALL DATA on the destination device!")
        print("="*60)

        final_confirm = input("Type 'PROCEED' to continue with imaging: ").strip()
        if final_confirm != 'PROCEED':
            self.log("Operation cancelled by user")
            sys.exit(0)

        # Perform imaging
        self.log("Starting forensic imaging process...")
        imaging_success = False

        if method_choice == '1':  # dd
            imaging_success = self.create_image_dd()
        elif method_choice == '2':  # ddrescue
            imaging_success = self.create_image_ddrescue()
        elif method_choice == '3':  # dd with pv
            imaging_success = self.create_image_dd_pv()

        if not imaging_success:
            self.log("Imaging process failed", "ERROR")

        # Verify integrity (even if imaging failed, for documentation)
        verification_success = self.verify_image_integrity()

        # Generate official imaging log
        log_file = self.generate_imaging_log()

        # Final summary
        print("\n" + "="*50)
        print("IMAGING COMPLETE")
        print("="*50)
        print(f"Imaging: {'SUCCESS' if imaging_success else 'FAILED'}")
        print(f"Verification: {'SUCCESS' if verification_success else 'FAILED'}")
        if log_file:
            print(f"Official Log: {log_file}")
        print("="*50)

        if imaging_success and verification_success:
            self.log("Forensic imaging completed successfully with verification", "SUCCESS")
            return 0
        else:
            self.log("Forensic imaging completed with issues - check logs", "WARNING")
            return 1 if not imaging_success else 0

if __name__ == "__main__":
    try:
        imager = ForensicImager()
        exit_code = imager.main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
