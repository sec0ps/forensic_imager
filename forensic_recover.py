#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Forensic Data Recovery Module
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
# Purpose: This module provides comprehensive data recovery capabilities
#          for deleted files and damaged filesystems. Supports multiple
#          filesystem types with GUI interface for ease of use.
#
# =============================================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import os
import json
import sys
import hashlib
import threading
from datetime import datetime
from pathlib import Path
import tempfile
import shutil

class ForensicDataRecovery:
    def __init__(self):
        # Check root privileges first (inline check)
        if os.geteuid() != 0:
            print("ERROR: This tool requires root privileges for device access and package installation")
            print("Please run with: sudo python3 forensic_recovery.py")
            sys.exit(1)

        self.root = tk.Tk()
        self.root.title("Forensic Data Recovery Tool - VAPT Toolkit")
        self.root.geometry("1200x800")

        self.source_device = None
        self.recovery_folder = None
        self.recovered_files = []
        self.temp_recovery_dir = None
        self.view_mode = tk.StringVar(value="table")
        self.search_var = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.log_entries = []

        # Enhanced dependency check with auto-install
        self.check_dependencies()
        self.setup_gui()

    def log(self, message, level="INFO"):
        """Add log entry with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        self.log_entries.append(log_entry)

        # Update log display if GUI is ready
        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, log_entry + "\n")
            self.log_text.see(tk.END)
        else:
            # Print to console if GUI not ready yet
            print(log_entry)

    def check_dependencies(self):
        """Check and automatically install required tools"""
        required_tools = {
            'testdisk': {'package': 'testdisk', 'version_cmd': ['testdisk', '--version']},
            'file': {'package': 'file', 'version_cmd': ['file', '--version']},
            'pdfinfo': {'package': 'poppler-utils', 'version_cmd': ['pdfinfo', '-v']},
            'exiftool': {'package': 'libimage-exiftool-perl', 'version_cmd': ['exiftool', '-ver']}
        }

        missing_packages = []

        print("Checking dependencies...")

        # Check which tools are missing
        for tool, config in required_tools.items():
            try:
                result = subprocess.run(config['version_cmd'], capture_output=True, check=True)
                print(f"✓ {tool} is available")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"✗ {tool} is missing (package: {config['package']})")
                missing_packages.append(config['package'])

        if missing_packages:
            print(f"\nMissing packages: {', '.join(missing_packages)}")
            print("Attempting to install missing dependencies...")

            try:
                # Update package lists
                print("Updating package lists...")
                subprocess.run(['apt', 'update'], capture_output=True, text=True, check=True)
                print("✓ Package lists updated")

                # Install missing packages
                install_cmd = ['apt', 'install', '-y'] + missing_packages
                print(f"Installing: {' '.join(missing_packages)}")

                subprocess.run(install_cmd, capture_output=True, text=True, check=True)
                print("✓ Dependencies installed successfully")

                # Verify installation with correct version commands
                print("Verifying installation...")
                for tool, config in required_tools.items():
                    try:
                        subprocess.run(config['version_cmd'], capture_output=True, check=True)
                        print(f"✓ {tool} verified")
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        print(f"✗ {tool} installation failed")
                        self.root.destroy()
                        sys.exit(1)

                print("✓ All dependencies installed and verified")

            except subprocess.CalledProcessError as e:
                print(f"✗ Failed to install dependencies: {e}")
                print(f"Please manually install: sudo apt install {' '.join(missing_packages)}")
                self.root.destroy()
                sys.exit(1)

        else:
            print("✓ All dependencies are already installed")

    def setup_gui(self):
        """Setup the GUI interface"""
        # Main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Recovery tab
        recovery_frame = ttk.Frame(notebook)
        notebook.add(recovery_frame, text="Data Recovery")

        # Source selection frame
        source_frame = ttk.LabelFrame(recovery_frame, text="Source Selection", padding=10)
        source_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(source_frame, text="Select Device", command=self.select_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(source_frame, text="Select Image File", command=self.select_image).pack(side=tk.LEFT, padx=5)
        self.source_label = ttk.Label(source_frame, text="No source selected")
        self.source_label.pack(side=tk.LEFT, padx=10)

        # Recovery options frame
        options_frame = ttk.LabelFrame(recovery_frame, text="Recovery Options", padding=10)
        options_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(options_frame, text="Scan for Files", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(options_frame, text="Recover Selected", command=self.recover_selected).pack(side=tk.LEFT, padx=5)

        # View mode selection
        ttk.Label(options_frame, text="View:").pack(side=tk.LEFT, padx=(20,5))
        ttk.Radiobutton(options_frame, text="Table", variable=self.view_mode, value="table", command=self.update_view).pack(side=tk.LEFT)
        ttk.Radiobutton(options_frame, text="Tree", variable=self.view_mode, value="tree", command=self.update_view).pack(side=tk.LEFT)

        # Search frame
        search_frame = ttk.LabelFrame(recovery_frame, text="Search", padding=10)
        search_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(search_frame, text="Search files:").pack(side=tk.LEFT)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        search_entry.bind('<KeyRelease>', self.filter_files)
        ttk.Button(search_frame, text="Search Content", command=self.search_content).pack(side=tk.LEFT, padx=5)

        # Progress bar
        self.progress = ttk.Progressbar(recovery_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, padx=5, pady=5)

        # Files display frame
        display_frame = ttk.LabelFrame(recovery_frame, text="Recoverable Files", padding=5)
        display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Create both table and tree views
        self.setup_table_view(display_frame)
        self.setup_tree_view(display_frame)

        # Selection controls
        select_frame = ttk.Frame(display_frame)
        select_frame.pack(fill=tk.X, pady=5)

        ttk.Button(select_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(select_frame, text="Deselect All", command=self.deselect_all).pack(side=tk.LEFT, padx=5)

        # Log tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Recovery Log")

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Button(log_frame, text="Save Log", command=self.save_log).pack(pady=5)

    def setup_table_view(self, parent):
        """Setup table view for files"""
        columns = ('select', 'filename', 'size', 'type', 'confidence', 'modified')
        self.table = ttk.Treeview(parent, columns=columns, show='headings', height=15)

        # Column headers
        self.table.heading('select', text='Select')
        self.table.heading('filename', text='Filename')
        self.table.heading('size', text='Size')
        self.table.heading('type', text='Type')
        self.table.heading('confidence', text='Confidence')
        self.table.heading('modified', text='Modified')

        # Column widths
        self.table.column('select', width=60)
        self.table.column('filename', width=300)
        self.table.column('size', width=100)
        self.table.column('type', width=100)
        self.table.column('confidence', width=100)
        self.table.column('modified', width=150)

        # Scrollbars
        table_scroll_v = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.table.yview)
        table_scroll_h = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.table.xview)
        self.table.configure(yscrollcommand=table_scroll_v.set, xscrollcommand=table_scroll_h.set)

        self.table.bind('<Button-1>', self.on_table_click)

    def setup_tree_view(self, parent):
        """Setup tree view for files"""
        self.tree = ttk.Treeview(parent, height=15)
        self.tree.heading('#0', text='Directory Structure')

        tree_scroll_v = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll_h = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_v.set, xscrollcommand=tree_scroll_h.set)

        self.tree.bind('<Button-1>', self.on_tree_click)

    def update_view(self):
        """Switch between table and tree view"""
        if self.view_mode.get() == "table":
            self.tree.pack_forget()
            self.table.pack(fill=tk.BOTH, expand=True)
        else:
            self.table.pack_forget()
            self.tree.pack(fill=tk.BOTH, expand=True)

    def select_device(self):
        """Select a device for recovery"""
        try:
            result = subprocess.run(['lsblk', '-J'], capture_output=True, text=True, check=True)
            devices = json.loads(result.stdout)

            device_list = []
            for device in devices['blockdevices']:
                if device['type'] == 'disk':
                    device_list.append(f"/dev/{device['name']} - {device.get('size', 'Unknown')} - {device.get('model', 'Unknown')}")

            if not device_list:
                messagebox.showerror("Error", "No devices found")
                return

            # Simple selection dialog
            selection = self.show_selection_dialog("Select Device", device_list)
            if selection:
                self.source_device = selection.split(' - ')[0]
                self.source_label.config(text=f"Device: {self.source_device}")
                self.log(f"Selected device: {self.source_device}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to list devices: {e}")
            self.log(f"Device selection error: {e}", "ERROR")

    def select_image(self):
        """Select an image file for recovery"""
        filename = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[("Image files", "*.img *.dd *.raw"), ("All files", "*.*")]
        )

        if filename:
            self.source_device = filename
            self.source_label.config(text=f"Image: {os.path.basename(filename)}")
            self.log(f"Selected image: {filename}")

    def show_selection_dialog(self, title, items):
        """Show selection dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        listbox = tk.Listbox(dialog)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for item in items:
            listbox.insert(tk.END, item)

        selected_item = None

        def on_select():
            nonlocal selected_item
            selection = listbox.curselection()
            if selection:
                selected_item = listbox.get(selection[0])
                dialog.destroy()

        ttk.Button(dialog, text="Select", command=on_select).pack(pady=5)

        dialog.wait_window()
        return selected_item

    def start_scan(self):
        """Start scanning for recoverable files"""
        if not self.source_device:
            messagebox.showerror("Error", "Please select a source device or image first")
            return

        self.log("Starting file recovery scan...")
        threading.Thread(target=self.scan_files, daemon=True).start()

    def scan_files(self):
        """Scan for recoverable files using photorec - REAL IMPLEMENTATION"""
        try:
            # Create temporary directory for scan results
            temp_dir = tempfile.mkdtemp(prefix="forensic_scan_")
            self.log(f"Scanning {self.source_device} for recoverable files...")
            self.log(f"Recovery output directory: {temp_dir}")

            # Update progress
            self.root.after(0, lambda: self.progress_var.set(10))

            # First, get partition information from the device
            try:
                # Use testdisk to list partitions
                testdisk_result = subprocess.run(['testdisk', '/list', self.source_device],
                                            capture_output=True, text=True, timeout=30)
                self.log(f"Testdisk partition info: {testdisk_result.stdout[:500]}")
            except Exception as e:
                self.log(f"Could not get partition info: {e}", "WARNING")

            # Run photorec with simplified command structure that works
            photorec_cmd = [
                'photorec',
                '/debug',
                '/cmd',
                self.source_device,
                'options,paranoid,keep_corrupted_file,enable',
                'fileopt,everything,enable',
                f'destination,{temp_dir}',
                'search'
            ]

            self.log(f"Running: {' '.join(photorec_cmd)}")

            # Execute photorec with timeout
            try:
                result = subprocess.run(photorec_cmd,
                                    capture_output=True,
                                    text=True,
                                    timeout=300,
                                    cwd=temp_dir)

                self.log(f"Photorec exit code: {result.returncode}")
                if result.stdout:
                    self.log(f"Photorec stdout: {result.stdout[:1000]}")
                if result.stderr:
                    self.log(f"Photorec stderr: {result.stderr[:1000]}")

                # Even if exit code is not 0, photorec might have found files
                if result.returncode != 0:
                    self.log(f"Photorec completed with exit code {result.returncode} (may still have recovered files)", "WARNING")

            except subprocess.TimeoutExpired:
                self.log("Photorec scan timed out - checking for partial results", "WARNING")
            except Exception as e:
                self.log(f"Photorec execution error: {e}", "ERROR")

            self.root.after(0, lambda: self.progress_var.set(70))

            # Parse recovered files from temp directory
            recovered_files = []
            self.log(f"Scanning directory: {temp_dir}")

            if os.path.exists(temp_dir):
                # Look for files in all subdirectories
                file_count = 0
                for root_path, dirs, files in os.walk(temp_dir):
                    self.log(f"Checking directory: {root_path} with {len(files)} files")

                    for file in files:
                        # Skip config files and logs
                        if file in ['photorec.cfg', 'photorec.log', 'report.xml']:
                            continue

                        # Look for recovered files (photorec creates files with various patterns)
                        if (file.startswith('f') and any(c.isdigit() for c in file)) or \
                        file.endswith(('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.doc', '.docx', '.mp3', '.mp4', '.avi', '.zip')):

                            filepath = os.path.join(root_path, file)
                            file_count += 1

                            try:
                                # Get file info
                                stat_info = os.stat(filepath)

                                # Format size inline
                                size_bytes = stat_info.st_size
                                if size_bytes == 0:
                                    size = "0B"
                                else:
                                    size_names = ["B", "KB", "MB", "GB", "TB"]
                                    i = 0
                                    while size_bytes >= 1024 and i < len(size_names) - 1:
                                        size_bytes /= 1024.0
                                        i += 1
                                    size = f"{size_bytes:.1f}{size_names[i]}"

                                # Detect file type inline
                                try:
                                    type_result = subprocess.run(['file', '--mime-type', filepath],
                                                        capture_output=True, text=True, check=True)
                                    mime_type = type_result.stdout.split(':')[1].strip()

                                    # Map common MIME types to user-friendly names
                                    type_mapping = {
                                        'application/pdf': 'PDF',
                                        'image/jpeg': 'JPEG Image',
                                        'image/png': 'PNG Image',
                                        'image/gif': 'GIF Image',
                                        'text/plain': 'Text File',
                                        'application/msword': 'Word Document',
                                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Word Document',
                                        'application/zip': 'ZIP Archive',
                                        'video/mp4': 'MP4 Video',
                                        'video/x-msvideo': 'AVI Video',
                                        'audio/mpeg': 'MP3 Audio',
                                        'audio/wav': 'WAV Audio'
                                    }

                                    file_type = type_mapping.get(mime_type, mime_type)
                                except Exception:
                                    # Fallback to extension-based detection
                                    ext = os.path.splitext(file)[1].lower()
                                    ext_mapping = {
                                        '.jpg': 'JPEG Image', '.jpeg': 'JPEG Image',
                                        '.png': 'PNG Image', '.gif': 'GIF Image',
                                        '.pdf': 'PDF', '.txt': 'Text File',
                                        '.doc': 'Word Document', '.docx': 'Word Document',
                                        '.mp3': 'MP3 Audio', '.wav': 'WAV Audio',
                                        '.mp4': 'MP4 Video', '.avi': 'AVI Video',
                                        '.zip': 'ZIP Archive'
                                    }
                                    file_type = ext_mapping.get(ext, "Unknown")

                                # Get original filename inline
                                original_name = None
                                try:
                                    # For PDF files, try to extract title
                                    if file_type == 'PDF':
                                        pdf_result = subprocess.run(['pdfinfo', filepath],
                                                            capture_output=True, text=True)
                                        for line in pdf_result.stdout.split('\n'):
                                            if line.startswith('Title:'):
                                                title = line.split(':', 1)[1].strip()
                                                if title and title not in ['Untitled', '']:
                                                    original_name = f"{title}.pdf"
                                                    break

                                    # For image files, check EXIF data
                                    elif 'Image' in file_type:
                                        exif_result = subprocess.run(['exiftool', '-FileName', filepath],
                                                            capture_output=True, text=True)
                                        if exif_result.returncode == 0:
                                            for line in exif_result.stdout.split('\n'):
                                                if 'File Name' in line:
                                                    filename = line.split(':', 1)[1].strip()
                                                    if filename:
                                                        original_name = filename
                                                        break
                                except Exception:
                                    pass  # Fall back to generated name

                                # Determine confidence based on file type detection
                                confidence = "High" if file_type != "Unknown" else "Low"

                                recovered_files.append({
                                    'filename': original_name or file,
                                    'size': size,
                                    'type': file_type,
                                    'confidence': confidence,
                                    'path': filepath,
                                    'modified': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                                })

                            except Exception as e:
                                self.log(f"Error processing file {file}: {e}", "WARNING")

                self.log(f"Total files found in scan: {file_count}")

            self.root.after(0, lambda: self.progress_var.set(100))
            self.root.after(0, lambda: self.populate_file_list(recovered_files))

            # Keep temp directory for recovery
            self.temp_recovery_dir = temp_dir

        except Exception as e:
            self.log(f"Scan error: {e}", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(e)))

    def populate_file_list(self, files):
        """Populate the file list display"""
        self.recovered_files = files

        # Clear existing items
        for item in self.table.get_children():
            self.table.delete(item)

        # Add files to table
        for file_info in files:
            self.table.insert('', tk.END, values=(
                '☐',  # Checkbox placeholder
                file_info['filename'],
                file_info['size'],
                file_info['type'],
                file_info['confidence'],
                'Unknown'
            ), tags=(file_info['path'],))

        self.log(f"Found {len(files)} recoverable files")

        # Update tree view if needed
        if self.view_mode.get() == "tree":
            self.populate_tree_view(files)

    def populate_tree_view(self, files):
        """Populate tree view with files organized by directory"""
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Group files by directory
        dirs = {}
        for file_info in files:
            dirname = os.path.dirname(file_info.get('path', '/unknown'))
            if dirname not in dirs:
                dirs[dirname] = []
            dirs[dirname].append(file_info)

        # Populate tree
        for dirname, dir_files in dirs.items():
            dir_node = self.tree.insert('', tk.END, text=dirname, open=True)
            for file_info in dir_files:
                self.tree.insert(dir_node, tk.END, text=file_info['filename'], tags=(file_info['path'],))

    def on_table_click(self, event):
        """Handle table click for checkbox selection"""
        item = self.table.identify('item', event.x, event.y)
        column = self.table.identify('column', event.x, event.y)

        if item and column == '#1':  # Select column
            current_values = list(self.table.item(item, 'values'))
            current_values[0] = '☑' if current_values[0] == '☐' else '☐'
            self.table.item(item, values=current_values)

    def on_tree_click(self, event):
        """Handle tree click for selection"""
        item = self.tree.identify('item', event.x, event.y)
        if item:
            # Toggle selection visual indicator
            current_text = self.tree.item(item, 'text')
            if current_text.startswith('☑'):
                self.tree.item(item, text=current_text[2:])
            elif not current_text.startswith('☐'):
                self.tree.item(item, text='☑ ' + current_text)

    def filter_files(self, event=None):
        """Filter files based on search term"""
        search_term = self.search_var.get().lower()

        # Clear and repopulate table with filtered results
        for item in self.table.get_children():
            self.table.delete(item)

        for file_info in self.recovered_files:
            if search_term in file_info['filename'].lower():
                self.table.insert('', tk.END, values=(
                    '☐',
                    file_info['filename'],
                    file_info['size'],
                    file_info['type'],
                    file_info['confidence'],
                    'Unknown'
                ), tags=(file_info['path'],))

    def search_content(self):
        """Search file content for text"""
        search_term = self.search_var.get()
        if not search_term:
            messagebox.showwarning("Search", "Please enter a search term")
            return

        self.log(f"Searching file content for: {search_term}")
        threading.Thread(target=self.perform_content_search, args=(search_term,), daemon=True).start()

    def perform_content_search(self, search_term):
        """Perform content search in recoverable files"""
        try:
            matching_files = []

            # Simulate content search
            for file_info in self.recovered_files:
                if file_info['type'] in ['Text', 'PDF']:  # Only search text files
                    # In real implementation, extract and search file content
                    if search_term.lower() in file_info['filename'].lower():
                        matching_files.append(file_info)

            self.root.after(0, lambda: self.show_search_results(matching_files, search_term))

        except Exception as e:
            self.log(f"Content search error: {e}", "ERROR")

    def show_search_results(self, results, search_term):
        """Show content search results"""
        if results:
            self.populate_file_list(results)
            self.log(f"Content search found {len(results)} files containing '{search_term}'")
        else:
            messagebox.showinfo("Search Results", f"No files found containing '{search_term}'")

    def select_all(self):
        """Select all visible files"""
        for item in self.table.get_children():
            current_values = list(self.table.item(item, 'values'))
            current_values[0] = '☑'
            self.table.item(item, values=current_values)

    def deselect_all(self):
        """Deselect all files"""
        for item in self.table.get_children():
            current_values = list(self.table.item(item, 'values'))
            current_values[0] = '☐'
            self.table.item(item, values=current_values)

    def recover_selected(self):
        """Recover selected files"""
        selected_files = []

        for item in self.table.get_children():
            values = self.table.item(item, 'values')
            if values[0] == '☑':
                file_path = self.table.item(item, 'tags')[0]
                selected_files.append({
                    'filename': values[1],
                    'path': file_path,
                    'size': values[2],
                    'type': values[3]
                })

        if not selected_files:
            messagebox.showwarning("Recovery", "No files selected for recovery")
            return

        # Create recovery folder
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        device_name = os.path.basename(self.source_device).replace('/', '_')
        self.recovery_folder = f"recovery_{device_name}_{timestamp}"

        try:
            os.makedirs(self.recovery_folder, exist_ok=True)
            self.log(f"Created recovery folder: {self.recovery_folder}")

            threading.Thread(target=self.perform_recovery, args=(selected_files,), daemon=True).start()

        except Exception as e:
            messagebox.showerror("Recovery Error", f"Failed to create recovery folder: {e}")

    def perform_recovery(self, selected_files):
        """Perform the actual file recovery """
        try:
            total_files = len(selected_files)
            recovery_log = []

            for i, file_info in enumerate(selected_files):
                self.progress_var.set((i / total_files) * 100)

                # Copy recovered file from temp directory to recovery folder
                source_path = file_info['path']
                output_path = os.path.join(self.recovery_folder, file_info['filename'])

                # Ensure unique filenames
                counter = 1
                base_name, ext = os.path.splitext(output_path)
                while os.path.exists(output_path):
                    output_path = f"{base_name}_{counter}{ext}"
                    counter += 1

                # Copy the actual recovered file
                shutil.copy2(source_path, output_path)

                # Calculate SHA-256 hash of recovered file
                sha256_hash = self.calculate_file_hash(output_path)

                # Get file metadata
                stat_info = os.stat(output_path)

                # Log recovery details with comprehensive metadata
                recovery_entry = {
                    'filename': file_info['filename'],
                    'original_path': file_info['path'],
                    'recovered_path': output_path,
                    'size_bytes': stat_info.st_size,
                    'size_formatted': file_info['size'],
                    'type': file_info['type'],
                    'confidence': file_info['confidence'],
                    'sha256': sha256_hash,
                    'timestamp': datetime.now().isoformat(),
                    'source_device': self.source_device,
                    'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    'access_time': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                    'creation_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                }

                recovery_log.append(recovery_entry)
                self.log(f"Recovered: {file_info['filename']} -> {output_path}")

            # Clean up temporary scan directory
            if hasattr(self, 'temp_recovery_dir') and os.path.exists(self.temp_recovery_dir):
                shutil.rmtree(self.temp_recovery_dir)
                self.log(f"Cleaned up temporary directory: {self.temp_recovery_dir}")

            # Save recovery log
            self.save_recovery_log(recovery_log)

            self.progress_var.set(100)
            self.root.after(0, lambda: messagebox.showinfo("Recovery Complete",
                f"Successfully recovered {total_files} files to {self.recovery_folder}"))

        except Exception as e:
            self.log(f"Recovery error: {e}", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Recovery Error", str(e)))

    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of recovered file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.log(f"Hash calculation error for {filepath}: {e}", "ERROR")
            return "ERROR"

    def save_recovery_log(self, recovery_log):
        """Save detailed recovery log"""
        log_filename = os.path.join(self.recovery_folder, "recovery_log.json")

        try:
            with open(log_filename, 'w') as f:
                json.dump({
                    'recovery_session': {
                        'timestamp': datetime.now().isoformat(),
                        'source': self.source_device,
                        'recovery_folder': self.recovery_folder,
                        'operator': os.getenv('USER', 'Unknown'),
                        'total_files': len(recovery_log)
                    },
                    'recovered_files': recovery_log,
                    'operation_log': self.log_entries
                }, f, indent=2)

            self.log(f"Recovery log saved: {log_filename}")

        except Exception as e:
            self.log(f"Failed to save recovery log: {e}", "ERROR")

    def save_log(self):
        """Save operation log to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Recovery Log"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("FORENSIC DATA RECOVERY LOG\n")
                    f.write("=" * 50 + "\n\n")
                    for entry in self.log_entries:
                        f.write(entry + "\n")

                messagebox.showinfo("Log Saved", f"Log saved to {filename}")

            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save log: {e}")

    def run(self):
        """Start the GUI application"""
        self.log("Forensic Data Recovery Tool started")
        self.root.mainloop()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Warning: This tool may require root privileges for device access")

    app = ForensicDataRecovery()
    app.run()
