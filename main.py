7#!/usr/bin/env python3
"""
Cartographer - Network Mapping and PII Detection Tool
Main entry point with command line interface
"""

import os
import sys
import time
import argparse
import logging
import subprocess
import webbrowser
import signal
import traceback
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

# Import memory-efficient storage
from memory_efficient_storage import get_memory_manager, DEFAULT_MAX_MEMORY_USAGE, DEFAULT_MAX_STORAGE

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('cartographer')

# Constants - Testing and Development
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
CAPTURE_DIR = SCRIPT_DIR / "captures"
DEFAULT_STORAGE_DIR = SCRIPT_DIR / "data_storage"

def configure_memory_storage(args):
    """Configure memory-efficient storage based on command line arguments"""
    # Create storage directory if it doesn't exist
    storage_dir = DEFAULT_STORAGE_DIR
    if args.storage_dir:
        storage_dir = Path(args.storage_dir)
    
    storage_dir.mkdir(exist_ok=True)
    
    # Set memory and storage limits
    memory_limit = args.memory_limit * 1024 * 1024 if args.memory_limit else DEFAULT_MAX_MEMORY_USAGE
    storage_limit = args.storage_limit * 1024 * 1024 * 1024 if args.storage_limit else DEFAULT_MAX_STORAGE
    
    # Set environment variables for subprocesses to use
    os.environ["MAX_MEMORY_USAGE"] = str(memory_limit)
    os.environ["MAX_STORAGE"] = str(storage_limit)
    os.environ["STORAGE_DIR"] = str(storage_dir)
    
    logger.info(f"Memory limit set to {memory_limit / 1024 / 1024:.1f}MB")
    logger.info(f"Storage limit set to {storage_limit / 1024 / 1024 / 1024:.1f}GB")
    logger.info(f"Storage directory: {storage_dir}")
    
    # Initialize the memory manager with our settings
    memory_manager = get_memory_manager()
    # Customize the memory manager settings
    memory_manager.max_memory = memory_limit
    memory_manager.disk_storage.max_storage = storage_limit
    memory_manager.disk_storage.storage_dir = storage_dir
    
    return memory_manager

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Cartographer - Network Mapping and PII Detection Tool"
    )
    
    # Proxy options
    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument(
        '-p', '--port', type=int, default=8080,
        help='Port for the MITM proxy to listen on (default: 8080)'
    )
    proxy_group.add_argument(
        '-i', '--interface', default='0.0.0.0',
        help='Interface for the MITM proxy to listen on (default: 0.0.0.0)'
    )
    proxy_group.add_argument(
        '--browser', action='store_true',
        help='Open default browser with proxy settings'
    )
    
    # Content filter options
    filter_group = parser.add_argument_group('Content Filtering')
    filter_group.add_argument(
        '--filter-content', default='',
        help='Content types to include, comma-separated (e.g., "text/html,application/json")'
    )
    filter_group.add_argument(
        '--exclude-content', default='',
        help='Content types to exclude, comma-separated'
    )
    
    # Memory management options
    memory_group = parser.add_argument_group('Memory Management')
    memory_group.add_argument(
        '--memory-limit', type=int, default=None,
        help='Memory usage limit in MB (default: 100MB)'
    )
    memory_group.add_argument(
        '--storage-limit', type=int, default=None,
        help='Disk storage limit in GB (default: 2GB)'
    )
    memory_group.add_argument(
        '--storage-dir', type=str, default=None,
        help=f'Directory for disk-based storage (default: {DEFAULT_STORAGE_DIR})'
    )
    memory_group.add_argument(
        '--cleanup-interval', type=int, default=None,
        help='Interval in seconds between automatic storage cleanup (default: 600)'
    )
    
    # Display options
    display_group = parser.add_argument_group('Display Options')
    display_group.add_argument(
        '--display-content', action='store_true',
        help='Display content in the console (default: False)'
    )
    display_group.add_argument(
        '--capture-binary', action='store_true',
        help='Capture binary content like images (default: False)'
    )
    display_group.add_argument(
        '--max-binary-size', type=int, default=1,
        help='Maximum size of binary content to capture in MB (default: 1MB)'
    )
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_args()
    
    try:
        # Create capture directories
        CAPTURE_DIR.mkdir(exist_ok=True)
        
        print(f"Cartographer - Network Mapping and PII Detection Tool")
        print(f"Captures will be saved to: {CAPTURE_DIR}")
        
        # Configure memory-efficient storage
        memory_manager = configure_memory_storage(args)
        
        # Set environment variables for the proxy
        if args.filter_content:
            os.environ["FILTER_CONTENT_TYPES"] = args.filter_content
            print(f"Filtering content types: {args.filter_content}")
            
        if args.exclude_content:
            os.environ["EXCLUDE_CONTENT_TYPES"] = args.exclude_content
            print(f"Excluding content types: {args.exclude_content}")
            
        if args.display_content:
            os.environ["DISPLAY_CONTENT"] = "1"
            
        if args.capture_binary:
            os.environ["CAPTURE_BINARY"] = "1"
            
        if args.max_binary_size:
            max_size = args.max_binary_size * 1024 * 1024  # Convert to bytes
            os.environ["MAX_BINARY_SIZE"] = str(max_size)
            
        # Start MITM proxy with our addon
        print(f"Starting proxy on {args.interface}:{args.port}")
        
        # Construct the proxy command
        proxy_cmd = [
            sys.executable, "-m", "mitmproxy.tools.main",
            "-p", str(args.port),
            "--listen-host", args.interface,
            "-s", str(SCRIPT_DIR / "mitm_proxy.py"),
            "--quiet"  # Reduce mitmproxy console output
        ]
        
        proxy_process = subprocess.Popen(proxy_cmd)
        
        # Give proxy time to start
        time.sleep(1)
        
        # Check if proxy started successfully
        if proxy_process.poll() is not None:
            print("Error: Proxy failed to start")
            sys.exit(1)
            
        print("Proxy started successfully")
        print(f"To use: Set your browser proxy to {args.interface}:{args.port}")
        print("To view recorded traffic, open a browser to captures/viewer.html")
        
        # Open browser with proxy settings if requested
        if args.browser:
            print("Opening browser with proxy settings...")
            # Open default browser with proxy settings
            # This is OS-specific and may need adjustment
            proxy_url = f"http://localhost:{args.port}"
            webbrowser.open(proxy_url)
        
        # Keep running until Ctrl+C
        try:
            while True:
                time.sleep(1)
                
                # Check memory stats every 30 seconds and log
                if int(time.time()) % 30 == 0:
                    stats = memory_manager.get_stats()
                    logger.info(f"Memory usage: {stats['total_memory_used_mb']:.2f}MB / {stats['memory_limit_mb']:.2f}MB ({stats['memory_usage_percent']:.1f}%)")
                    logger.info(f"Disk storage: {stats['disk_storage']['storage_used_mb']:.2f}MB / {stats['disk_storage']['storage_limit_gb']*1024:.2f}MB ({stats['disk_storage']['usage_percent']:.1f}%)")
                    
        except KeyboardInterrupt:
            print("\nStopping proxy...")
            proxy_process.terminate()
            proxy_process.wait()
            print("Proxy stopped")
            
            # Clean up and show final stats
            print("\nFinal Memory Usage Statistics:")
            stats = memory_manager.get_stats()
            print(f"Memory used: {stats['total_memory_used_mb']:.2f}MB / {stats['memory_limit_mb']:.2f}MB ({stats['memory_usage_percent']:.1f}%)")
            print(f"Disk storage used: {stats['disk_storage']['storage_used_mb']:.2f}MB / {stats['disk_storage']['storage_limit_gb']*1024:.2f}MB ({stats['disk_storage']['usage_percent']:.1f}%)")
            print(f"Text buffer entries: {stats['text_buffer']['size']}")
            print(f"Binary buffer entries: {stats['binary_buffer']['size']}")
            print(f"Metadata buffer entries: {stats['metadata_buffer']['size']}")
            print("\nCaptures saved to:", CAPTURE_DIR)
    
    except Exception as e:
        print(f"Error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()