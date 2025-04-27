#!/usr/bin/env python3
"""
Network Traffic Monitor for PII Detection
Captures HTTP/S traffic and identifies content types using magic byte detection
"""

import pyshark
import binascii
import re
import logging
import numpy as np
import time
from typing import Dict, List, Optional, Tuple, Union
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('network_monitor')

# Magic byte signatures for common file/content types
MAGIC_BYTES = {
    # Text formats
    'text/plain': [(b'\xEF\xBB\xBF', 'UTF-8 BOM'), (b'', 'ASCII/UTF-8')],  # Empty bytes also match for plain text
    'text/html': [(b'<!DOCTYPE html>', None), (b'<html', None)],
    'text/xml': [(b'<?xml', None), (b'<xml', None)],
    'text/css': [(b'@charset', None), (b'body{', None), (b'.', None)],  # CSS often starts with these
    'application/json': [(b'{', None), (b'[', None)],
    
    # Document formats
    'application/pdf': [(b'%PDF', None)],
    'application/msword': [(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', None)],  # DOC
    'application/vnd.openxmlformats': [(b'PK\x03\x04', None)],  # DOCX, XLSX, PPTX
    
    # Image formats
    'image/jpeg': [(b'\xFF\xD8\xFF', None)],
    'image/png': [(b'\x89PNG\r\n\x1A\n', None)],
    'image/gif': [(b'GIF87a', None), (b'GIF89a', None)],
    'image/webp': [(b'RIFF', None)],
    
    # Compressed formats
    'application/zip': [(b'PK\x03\x04', None)],
    'application/gzip': [(b'\x1F\x8B\x08', None)],
    'application/x-7z-compressed': [(b'7z\xBC\xAF\x27\x1C', None)],
}

# PII patterns to search for in text content
PII_PATTERNS = {
    'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'ssn': re.compile(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'),
    'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    'phone_number': re.compile(r'\b(\+\d{1,2}\s?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
}

# Pre-compile regex patterns for better performance
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
PHONE_PATTERN = re.compile(r'(\+\d{1,3}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}')
SSN_PATTERN = re.compile(r'\d{3}-\d{2}-\d{4}')
CREDIT_CARD_PATTERN = re.compile(r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})')
IP_ADDRESS_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
ADDRESS_PATTERN = re.compile(r'\d+\s+[A-Za-z0-9\s,]+\b(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|parkway|pkwy|circle|cir|boulevard|blvd)\b', re.IGNORECASE)
ZIP_CODE_PATTERN = re.compile(r'\b\d{5}(?:-\d{4})?\b')
DATE_OF_BIRTH_PATTERN = re.compile(r'\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b')
API_KEY_PATTERN = re.compile(r'(?:api[_-]?key|access[_-]?token)["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\'"]?', re.IGNORECASE)
PASSWORD_PATTERN = re.compile(r'(?:password|passwd|pwd)["\']?\s*[=:]\s*["\']?([^"\']{6,})', re.IGNORECASE)
JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')

def detect_content_type(data: bytes) -> str:
    """
    Optimized function to detect content type using magic bytes detection
    
    Args:
        data: Binary data to analyze
        
    Returns:
        String representing the detected content type
    """
    if not data:
        return "unknown/empty"
    
    # Fast path: Check common text patterns first for performance
    # Most web traffic will be HTML or text
    if data.startswith(b'<!DOCTYPE html>') or data.startswith(b'<html'):
        return 'text/html'
    if data.startswith(b'{') or data.startswith(b'['):
        return 'application/json'
    if data.startswith(b'<?xml') or data.startswith(b'<xml'):
        return 'text/xml'
        
    # For other types, check magic bytes
    for content_type, signatures in MAGIC_BYTES.items():
        for signature, _ in signatures:
            # Skip empty signatures for better performance
            if signature and data.startswith(signature):
                return content_type
                
    # If we can't determine a specific type but it looks like text, call it text/plain
    # Use a smaller sample size for faster processing
    if is_probably_text(data, sample_size=50):
        return "text/plain"
        
    return "application/octet-stream"  # Default to binary

def is_probably_text(data: bytes, sample_size: int = 50) -> bool:
    """
    NumPy-optimized function to check if data is likely text by sampling bytes
    
    Args:
        data: Binary data to analyze
        sample_size: Number of bytes to sample
        
    Returns:
        True if data is likely text, False otherwise
    """
    # Fast path: Very short data
    if not data:
        return False
    
    # Sample the data and convert to numpy array for faster processing
    sample = np.frombuffer(data[:min(len(data), sample_size)], dtype=np.uint8)
    
    if len(sample) == 0:
        return False
    
    # Vectorized operation instead of iterating
    # Count characters not in printable ASCII range
    non_printable = np.logical_or.reduce([
        sample < 9,
        np.logical_and(sample > 13, sample < 32),
        sample > 126
    ])
    
    binary_ratio = np.mean(non_printable)
    return binary_ratio <= 0.1  # Less than 10% binary characters indicates text

def scan_for_pii(content: str) -> Dict[str, List[str]]:
    """
    Optimized function to scan text content for potential PII
    
    Args:
        content: String content to scan
        
    Returns:
        Dictionary with PII types as keys and lists of matches as values
    """
    results = {}
    
    # Only process content if it's not too long (improves performance)
    if len(content) > 1_000_000:  # 1MB limit
        content = content[:1_000_000]  # Truncate very large content
    
    # Fast path: Skip if content is very short or doesn't contain common PII indicators
    if len(content) < 10:
        return results
        
    # Check for common PII indicators before running expensive regex
    quick_indicators = {
        'email': '@',
        'ssn': '-',
        'credit_card': ['4', '5', '3', '6'],  # Common CC first digits
        'phone_number': ['(', ')', '+'],
        'ip_address': '.'
    }
    
    # Only run patterns for PII types that are likely present based on indicators
    for pii_type, indicators in quick_indicators.items():
        should_check = False
        
        if isinstance(indicators, str):
            should_check = indicators in content
        else:
            # For lists of indicators, check each one
            should_check = any(ind in content for ind in indicators)
            
        if should_check:
            pattern = PII_PATTERNS[pii_type]
            matches = pattern.findall(content)
            if matches:
                # Limit the number of matches to avoid memory issues
                results[pii_type] = matches[:100]
            
    return results

def batch_process_packets(packet_batch):
    """
    Process a batch of packets using NumPy for vectorized operations
    
    Args:
        packet_batch: List of packet info dictionaries to process
        
    Returns:
        Processed packet data and statistics
    """
    # Extract features that can be processed in parallel
    # For example, extracting all IP addresses for parallel processing
    if not packet_batch:
        return [], 0, 0, 0
    
    src_ips = np.array([p.get('src_ip', '') for p in packet_batch])
    dst_ips = np.array([p.get('dst_ip', '') for p in packet_batch])
    
    # Count packet types in one pass using NumPy
    protocols = np.array([p.get('protocol', '') for p in packet_batch])
    http_packets = np.sum(protocols == 'HTTP')
    https_packets = np.sum(protocols == 'HTTPS')
    
    # Process all text payloads at once if they're similar format
    # This is a simplistic example - real implementation would need more logic
    pii_count = 0
    
    return packet_batch, http_packets, https_packets, pii_count

def capture_network_traffic(interface: str, 
                           capture_filter: str = "", 
                           duration: int = 60) -> List[Dict]:
    """
    Capture network traffic on specified interface with NumPy optimizations
    
    Args:
        interface: Network interface to capture on
        capture_filter: BPF filter string (e.g. "tcp port 80 or tcp port 443")
        duration: Duration in seconds to capture
        
    Returns:
        List of dictionaries containing packet information and content type
    """
    logger.info(f"Starting capture on interface {interface} for {duration} seconds")
    print(f"Starting packet capture on {interface}...")
    
    # Initialize capture
    try:
        # Print debug info
        print(f"Setting up capture with filter: {capture_filter or 'None'}")
        
        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter="http or ssl",
            bpf_filter=capture_filter,
            include_raw=True,  # Include raw packet data for faster processing
            use_json=True,     # Use JSON output for faster parsing
            output_file=None   # Don't save to disk by default
        )
        
        print(f"Sniffing packets for {duration} seconds...")
        # Set capture timeout
        capture.sniff(timeout=duration)
        print(f"Finished sniffing, processing packets...")
        
        results = []
        packet_count = 0
        http_count = 0
        https_count = 0
        pii_found_count = 0
        last_update_time = time.time()
        update_interval = 1.0  # Update progress every 1 second
        
        # Batch processing for vectorized operations
        batch_size = 100
        current_batch = []
        
        try:
            # Check if tqdm is available for progress bar
            from tqdm import tqdm
            use_progress_bar = True
        except ImportError:
            use_progress_bar = False
            print("Tip: Install tqdm package for progress bar (pip install tqdm)")
        
        if use_progress_bar:
            pbar = tqdm(desc="Processing packets", unit="packets")
        
        for packet in capture:
            packet_count += 1
            
            # Update progress less frequently to reduce terminal spam
            current_time = time.time()
            if current_time - last_update_time > update_interval:
                if use_progress_bar:
                    pbar.update(packet_count - pbar.n)
                else:
                    print(f"Processed {packet_count} packets so far (HTTP: {http_count}, HTTPS: {https_count}, PII: {pii_found_count})")
                last_update_time = current_time
            
            # Fast path: Skip processing packets without IP layer
            if not hasattr(packet, 'ip'):
                continue
                
            # Create minimal packet_info with only necessary fields
            packet_info = {
                'timestamp': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else None,
                'src_ip': packet.ip.src if hasattr(packet, 'ip') else None,
                'dst_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
                'protocol': None,
                'payload': None,  # Will store payload data for batch processing
                'content_type': None
            }
            
            # Extract basic protocol info
            if hasattr(packet, 'http'):
                packet_info['protocol'] = 'HTTP'
                http_count += 1
                
                # Extract payload for batch processing later
                if hasattr(packet.http, 'file_data'):
                    try:
                        raw_data = packet.http.file_data.replace(':', '')
                        packet_info['payload'] = bytes.fromhex(raw_data)
                    except Exception as e:
                        logger.debug(f"Error extracting payload: {str(e)}")
                
            elif hasattr(packet, 'ssl'):
                packet_info['protocol'] = 'HTTPS'
                https_count += 1
            
            # Add to current batch for vectorized processing
            current_batch.append(packet_info)
            
            # Process batch when it reaches batch_size
            if len(current_batch) >= batch_size:
                # Process payloads and content types in batch
                process_payload_batch(current_batch)
                
                # Count PII in this batch
                batch_pii = sum(1 for p in current_batch if p.get('pii_detected'))
                pii_found_count += batch_pii
                
                results.extend(current_batch)
                current_batch = []
        
        # Process final batch
        if current_batch:
            process_payload_batch(current_batch)
            batch_pii = sum(1 for p in current_batch if p.get('pii_detected'))
            pii_found_count += batch_pii
            results.extend(current_batch)
        
        if use_progress_bar:
            pbar.close()
        
        logger.info(f"Captured {packet_count} packets (HTTP: {http_count}, HTTPS: {https_count}, PII found: {pii_found_count})")
        print(f"\nProcessed {len(results)} packets (HTTP: {http_count}, HTTPS: {https_count}, PII found: {pii_found_count})")
        return results
        
    except Exception as e:
        logger.error(f"Error during packet capture: {str(e)}")
        print(f"ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return []

def process_payload_batch(packet_batch):
    """
    Process a batch of payloads for content type detection and PII scanning
    
    Args:
        packet_batch: List of packet dictionaries with payload data
    """
    # Extract content types for all payloads in batch
    for packet in packet_batch:
        if packet['payload'] is not None:
            payload = packet['payload']
            content_type = detect_content_type(payload)
            packet['content_type'] = content_type
            
            # Only process text-based content
            if content_type.startswith('text/') or content_type == 'application/json':
                try:
                    text_content = payload.decode('utf-8', errors='replace')
                    pii_results = scan_for_pii(text_content)
                    
                    if pii_results:
                        packet['pii_detected'] = pii_results
                        print(f"Found HTTP packet with PII: {packet['src_ip']} -> {packet['dst_ip']}")
                        print(f"  - Content type: {content_type}")
                        print(f"  - PII detected: {list(pii_results.keys())}")
                except Exception as e:
                    logger.debug(f"Error processing content: {str(e)}")
    
    # Remove the raw payload data to free up memory
    for packet in packet_batch:
        if 'payload' in packet:
            del packet['payload']

def analyze_traffic_patterns(packets):
    """
    Use NumPy to analyze network traffic patterns from captured packets
    
    Args:
        packets: List of packet dictionaries
        
    Returns:
        Dictionary with analysis results
    """
    if not packets:
        return {}
        
    # Convert relevant packet data to NumPy arrays for vectorized processing
    timestamps = []
    src_ips = []
    dst_ips = []
    protocols = []
    
    for p in packets:
        if p.get('timestamp'):
            timestamps.append(p.get('timestamp'))
        if p.get('src_ip'):
            src_ips.append(p.get('src_ip'))
        if p.get('dst_ip'):
            dst_ips.append(p.get('dst_ip'))
        if p.get('protocol'):
            protocols.append(p.get('protocol'))
    
    # Convert lists to numpy arrays for faster processing
    src_ips_arr = np.array(src_ips)
    dst_ips_arr = np.array(dst_ips)
    protocols_arr = np.array(protocols)
    
    # Calculate traffic statistics
    results = {}
    
    # Count unique IPs
    results['unique_src_ips'] = len(np.unique(src_ips_arr))
    results['unique_dst_ips'] = len(np.unique(dst_ips_arr))
    
    # Calculate protocol distribution
    unique_protocols, protocol_counts = np.unique(protocols_arr, return_counts=True)
    results['protocol_distribution'] = {p: c for p, c in zip(unique_protocols, protocol_counts)}
    
    # Find top source and destination IPs
    if len(src_ips_arr) > 0:
        unique_srcs, src_counts = np.unique(src_ips_arr, return_counts=True)
        top_indices = np.argsort(-src_counts)[:5]  # Top 5 sources
        results['top_src_ips'] = {unique_srcs[i]: int(src_counts[i]) for i in top_indices}
    
    if len(dst_ips_arr) > 0:
        unique_dsts, dst_counts = np.unique(dst_ips_arr, return_counts=True)
        top_indices = np.argsort(-dst_counts)[:5]  # Top 5 destinations
        results['top_dst_ips'] = {unique_dsts[i]: int(dst_counts[i]) for i in top_indices}
    
    return results

def real_time_monitor(interface: str,
                    capture_filter: str = "tcp port 80 or tcp port 443",
                    duration: int = None):
    """
    Real-time network traffic monitor that processes packets as they arrive
    
    Args:
        interface: Network interface to capture on
        capture_filter: BPF filter string
        duration: Optional duration in seconds (None for continuous monitoring)
        
    Returns:
        Dictionary containing monitoring statistics
    """
    logger.info(f"Starting real-time monitoring on interface {interface}")
    print(f"Starting real-time packet monitoring on {interface}...")
    
    # Statistics counters
    stats = {
        'total_packets': 0,
        'http_packets': 0,
        'https_packets': 0,
        'pii_detected': 0,
        'start_time': time.time(),
        'pii_types': defaultdict(int)
    }
    
    # Set up alert thresholds
    alert_threshold = {
        'email': 5,      # Alert if more than 5 emails detected
        'ssn': 1,        # Alert immediately for any SSN
        'credit_card': 1 # Alert immediately for any credit card
    }
    
    def packet_callback(packet):
        """Callback function that processes each packet as it arrives"""
        stats['total_packets'] += 1
        
        # Skip packets without IP layer
        if not hasattr(packet, 'ip'):
            return
            
        # Process the packet
        src_ip = packet.ip.src if hasattr(packet, 'ip') else None
        dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
        
        # Process HTTP packets
        if hasattr(packet, 'http'):
            stats['http_packets'] += 1
            
            # Only process if there's payload data
            if hasattr(packet.http, 'file_data'):
                try:
                    # Extract and process payload in real-time
                    raw_data = packet.http.file_data.replace(':', '')
                    payload = bytes.fromhex(raw_data)
                    content_type = detect_content_type(payload)
                    
                    # Process text content for PII
                    if content_type.startswith('text/') or content_type == 'application/json':
                        text_content = payload.decode('utf-8', errors='replace')
                        pii_results = scan_for_pii(text_content)
                        
                        if pii_results:
                            stats['pii_detected'] += 1
                            
                            # Real-time alert for PII detection
                            print(f"\n[!] PII DETECTED at {time.strftime('%H:%M:%S')}")
                            print(f"    Source: {src_ip} → {dst_ip}")
                            print(f"    Content-Type: {content_type}")
                            
                            # Track PII types and check thresholds
                            for pii_type, matches in pii_results.items():
                                stats['pii_types'][pii_type] += len(matches)
                                
                                # Check if we should generate an alert based on thresholds
                                if (pii_type in alert_threshold and 
                                    stats['pii_types'][pii_type] >= alert_threshold[pii_type]):
                                    print(f"    [ALERT] {pii_type.upper()} threshold exceeded!")
                                
                                # Show a sample of the detected PII (safely redacted)
                                if matches and pii_type != 'ip_address':  # Don't redact IPs
                                    sample = matches[0]
                                    redacted = redact_pii(sample, pii_type)
                                    print(f"    {pii_type}: {redacted}")
                
                except Exception as e:
                    logger.debug(f"Error processing HTTP content: {str(e)}")
        
        # Process HTTPS packets (limited info due to encryption)
        elif hasattr(packet, 'ssl'):
            stats['https_packets'] += 1
        
        # Display periodic status updates
        if stats['total_packets'] % 100 == 0:
            elapsed = time.time() - stats['start_time']
            packets_per_sec = stats['total_packets'] / elapsed if elapsed > 0 else 0
            print(f"\rMonitoring: {stats['total_packets']} packets ({packets_per_sec:.1f}/s) | "
                  f"HTTP: {stats['http_packets']} | HTTPS: {stats['https_packets']} | "
                  f"PII: {stats['pii_detected']}", end='')
    
    try:
        # Set up live capture with callback
        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter="http or ssl",
            bpf_filter=capture_filter,
            include_raw=True,
            use_json=True  # Added this parameter to fix the error
        )
        
        print(f"Beginning real-time monitoring (Ctrl+C to stop)...")
        
        if duration:
            # Monitor for specified duration
            capture.apply_on_packets(packet_callback, timeout=duration)
        else:
            # Continuous monitoring until manually stopped
            capture.apply_on_packets(packet_callback)
            
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")
    except Exception as e:
        logger.error(f"Error during real-time capture: {str(e)}")
        print(f"ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
    finally:
        # Display summary statistics
        elapsed = time.time() - stats['start_time']
        print("\n\n--- Monitoring Summary ---")
        print(f"Duration: {elapsed:.1f} seconds")
        print(f"Total packets: {stats['total_packets']}")
        print(f"HTTP packets: {stats['http_packets']}")
        print(f"HTTPS packets: {stats['https_packets']}")
        print(f"PII detections: {stats['pii_detected']}")
        
        if stats['pii_types']:
            print("\nPII types detected:")
            for pii_type, count in stats['pii_types'].items():
                print(f"  - {pii_type}: {count}")
        
        return stats

def redact_pii(text, pii_type):
    """Safely redact PII for display purposes"""
    if pii_type == 'email':
        parts = text.split('@')
        if len(parts) == 2:
            return f"{parts[0][:2]}***@{parts[1]}"
    elif pii_type in ['ssn', 'credit_card']:
        return "***" + text[-4:] if len(text) >= 4 else "****"
    elif pii_type == 'phone_number':
        return "***-***-" + text[-4:] if len(text) >= 4 else "****"
    
    # Default redaction
    return text[:2] + "****" if len(text) > 2 else "****"

def main():
    """Main function for testing"""
    import json
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Traffic Monitor for PII Detection')
    parser.add_argument('interface', help='Network interface to monitor (e.g., en0, eth0)')
    parser.add_argument('-d', '--duration', type=int, default=None, 
                        help='Duration in seconds to monitor (default: continuous until Ctrl+C)')
    parser.add_argument('-f', '--filter', default="tcp port 80 or tcp port 443", 
                        help='BPF capture filter (default: "tcp port 80 or tcp port 443")')
    parser.add_argument('-r', '--real-time', action='store_true', 
                        help='Use real-time processing mode (recommended)')
    parser.add_argument('-b', '--batch', action='store_true',
                        help='Use batch processing mode (legacy)')
    parser.add_argument('--save', action='store_true',
                        help='Automatically save results to file')
    
    args = parser.parse_args()
    
    interface = args.interface
    duration = args.duration
    capture_filter = args.filter
    
    # Display interface information
    try:
        import netifaces
        print(f"Available network interfaces: {netifaces.interfaces()}")
    except ImportError:
        print("Note: Install netifaces package for interface listing (pip install netifaces)")
    
    # Check for root/sudo permissions
    import os
    if os.geteuid() != 0:
        print("WARNING: Not running as root/sudo. Packet capture may have limited permissions.")
        print(f"Try running with: sudo python network_monitor.py {interface}")
    
    print(f"Starting monitor on {interface} with filter: {capture_filter}")
    
    # Choose processing mode - default to real-time unless batch is specified
    if args.batch:
        print("Using batch processing mode")
        results = capture_network_traffic(
            interface=interface,
            capture_filter=capture_filter,
            duration=duration if duration else 30  # Default 30s for batch mode
        )
        
        if results:
            # Legacy batch processing analysis
            print("\nAnalyzing traffic patterns...")
            analysis = analyze_traffic_patterns(results)
            print(f"\nTraffic Analysis Results:")
            print(json.dumps(analysis, indent=2))
            
            # Count PII instances
            pii_counts = defaultdict(int)
            for packet in results:
                for pii_type, instances in packet.get('pii_detected', {}).items():
                    pii_counts[pii_type] += len(instances)
            
            print(f"\nCaptured {len(results)} packets")
            print(f"PII detected: {json.dumps(dict(pii_counts), indent=2)}")
            
            # Save results if requested or prompted
            save_results = args.save or input("\nSave full results to file? (y/n): ").lower() == 'y'
            if save_results:
                filename = f"network_capture_{interface}.json"
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"Results saved to {filename}")
        else:
            print("\nNo packets captured to save.")
            print_troubleshooting_tips()
    else:
        # Use real-time monitoring (recommended)
        print("Using real-time processing mode")
        stats = real_time_monitor(
            interface=interface,
            capture_filter=capture_filter,
            duration=duration
        )
        
        # After monitoring completes or is interrupted
        if args.save and stats and stats['total_packets'] > 0:
            filename = f"network_monitor_stats_{interface}.json"
            with open(filename, 'w') as f:
                # Convert defaultdict to regular dict for JSON serialization
                stats_copy = {k: v if not isinstance(v, defaultdict) else dict(v) 
                             for k, v in stats.items()}
                json.dump(stats_copy, f, indent=2, default=str)
            print(f"Statistics saved to {filename}")

def print_troubleshooting_tips():
    """Print helpful troubleshooting tips for common issues"""
    print("Troubleshooting tips:")
    print("1. Ensure you have the right interface name")
    print("2. Run with sudo permissions (sudo python network_monitor.py <interface>)")
    print("3. Generate some HTTP traffic (open web pages) during capture")
    print("4. Try a longer duration")
    print("5. Check if a firewall is blocking traffic")
    print("6. If monitoring HTTPS, note that content cannot be inspected due to encryption")

if __name__ == "__main__":
    main()