#!/usr/bin/env python3
"""
Streaming parsers for handling large payloads efficiently in Cartographer
"""

import io
import os
import re
import json
import asyncio
import logging
from typing import Dict, List, Any, Tuple, Set, Optional, Union, BinaryIO, Generator, AsyncGenerator

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('streaming_parsers')

# Default chunk size (8KB is a good balance for most network operations)
DEFAULT_CHUNK_SIZE = 8 * 1024

class StreamingParser:
    """
    Base class for streaming parsers that process data in chunks
    to avoid loading entire payloads into memory
    """
    
    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Initialize parser with given chunk size"""
        self.chunk_size = chunk_size
    
    def parse_stream(self, stream: BinaryIO) -> Generator[Any, None, None]:
        """
        Parse a binary stream in chunks
        
        Args:
            stream: A file-like object containing binary data
            
        Returns:
            Generator yielding processed chunks
        """
        raise NotImplementedError("Subclasses must implement parse_stream")
    
    async def parse_stream_async(self, stream: BinaryIO) -> AsyncGenerator[Any, None]:
        """
        Parse a binary stream in chunks asynchronously
        
        Args:
            stream: A file-like object containing binary data
            
        Returns:
            AsyncGenerator yielding processed chunks
        """
        for chunk in self.parse_stream(stream):
            # Allow other tasks to run between chunks
            await asyncio.sleep(0)
            yield chunk

class StreamingJSONParser(StreamingParser):
    """
    Parse JSON data in a streaming fashion to avoid loading entire
    JSON documents into memory
    """
    
    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE, extract_path: str = None):
        """
        Initialize parser
        
        Args:
            chunk_size: Size of chunks to process at once
            extract_path: Optional JSON path to extract (e.g. "data.items")
        """
        super().__init__(chunk_size)
        self.extract_path = extract_path
        self.buffer = b''
        self.depth = 0
        self.in_string = False
        self.escaped = False
        
    def parse_stream(self, stream: BinaryIO) -> Generator[Dict, None, None]:
        """
        Parse JSON from a stream, yielding complete objects as they are found
        
        This handles streaming JSON arrays and objects by tracking brackets depth
        """
        # Read the first chunk to detect if we're parsing an array or object
        chunk = stream.read(self.chunk_size)
        if not chunk:
            return
            
        self.buffer += chunk
        
        # Determine if we're parsing an array or a standalone object
        parsing_array = False
        for i, char in enumerate(self.buffer):
            if char == ord(b'{'):
                break
            elif char == ord(b'['):
                parsing_array = True
                break
            elif not chr(char).isspace():
                # If it's not whitespace and not [ or {, something is wrong
                raise ValueError("Invalid JSON: expected object or array")
        
        # Process the first chunk and reset the stream position if needed
        object_buffer = b""
        inside_object = False
        start_idx = -1
        
        while True:
            # Process the buffer character by character
            i = 0
            while i < len(self.buffer):
                char = self.buffer[i]
                
                # Track if we're inside a string
                if char == ord(b'"') and not self.escaped:
                    self.in_string = not self.in_string
                
                # Track if the next character is escaped
                if char == ord(b'\\') and not self.escaped:
                    self.escaped = True
                else:
                    self.escaped = False
                
                # Only count brackets if we're not inside a string
                if not self.in_string:
                    if char == ord(b'{'):
                        self.depth += 1
                        if self.depth == 1 and not parsing_array:
                            # Start of a new object
                            start_idx = i
                            inside_object = True
                        elif self.depth == 2 and parsing_array:
                            # Start of a new object inside an array
                            start_idx = i
                            inside_object = True
                    
                    elif char == ord(b'}'):
                        self.depth -= 1
                        if self.depth == 0 and not parsing_array:
                            # End of the object
                            object_buffer = self.buffer[start_idx:i+1]
                            try:
                                obj = json.loads(object_buffer)
                                yield obj
                            except json.JSONDecodeError as e:
                                logger.error(f"JSON decode error: {e}")
                            
                            inside_object = False
                            start_idx = -1
                        elif self.depth == 1 and parsing_array:
                            # End of an object inside an array
                            object_buffer = self.buffer[start_idx:i+1]
                            try:
                                obj = json.loads(object_buffer)
                                yield obj
                            except json.JSONDecodeError as e:
                                logger.error(f"JSON decode error: {e}")
                            
                            inside_object = False
                            start_idx = -1
                
                i += 1
            
            # Clear processed data from buffer, keeping any incomplete objects
            if start_idx >= 0:
                self.buffer = self.buffer[start_idx:]
            else:
                self.buffer = b''
            
            # Read next chunk
            chunk = stream.read(self.chunk_size)
            if not chunk:
                # End of stream
                break
                
            self.buffer += chunk
        
        # Process any remaining complete JSON object at the end
        if inside_object and self.depth == 0:
            try:
                obj = json.loads(self.buffer)
                yield obj
            except json.JSONDecodeError:
                pass

class StreamingTextParser(StreamingParser):
    """
    Parse text content in chunks, applying regex patterns to each chunk
    with proper handling of chunk boundaries
    """
    
    def __init__(self, 
                regex_patterns: Dict[str, re.Pattern], 
                chunk_size: int = DEFAULT_CHUNK_SIZE,
                overlap: int = 100):
        """
        Initialize parser with regex patterns to search for
        
        Args:
            regex_patterns: Dictionary mapping names to compiled regex patterns
            chunk_size: Size of chunks to process at once
            overlap: Number of bytes to overlap between chunks to avoid missing matches at boundaries
        """
        super().__init__(chunk_size)
        self.regex_patterns = regex_patterns
        self.overlap = overlap
        
    def parse_stream(self, stream: BinaryIO) -> Generator[Dict[str, List[str]], None, None]:
        """
        Parse text stream and yield regex matches in chunks
        
        Handles overlapping between chunks to ensure patterns that cross
        chunk boundaries are still detected.
        """
        previous_chunk = b""
        
        while True:
            chunk = stream.read(self.chunk_size)
            if not chunk:
                # Process the last chunk if there's any remaining data
                if previous_chunk:
                    yield self._process_chunk(previous_chunk)
                break
                
            # Combine with overlap from previous chunk
            data = previous_chunk[-self.overlap:] + chunk if previous_chunk else chunk
            
            # Process the current chunk
            matches = self._process_chunk(data)
            yield matches
            
            # Store current chunk for overlap processing
            previous_chunk = chunk
    
    def _process_chunk(self, data: bytes) -> Dict[str, List[str]]:
        """
        Process a single chunk of data with all regex patterns
        
        Args:
            data: Binary data chunk
            
        Returns:
            Dictionary of pattern names to lists of matches
        """
        results = {}
        
        try:
            # Convert to text using a forgiving encoding
            text = data.decode('utf-8', errors='replace')
            
            # Apply each regex pattern
            for pattern_name, pattern in self.regex_patterns.items():
                matches = pattern.findall(text)
                if matches:
                    # Limit matches to avoid memory issues
                    results[pattern_name] = matches[:100]
        except Exception as e:
            logger.error(f"Error processing text chunk: {e}")
        
        return results

class StreamingHTMLParser(StreamingParser):
    """
    Process HTML content in chunks, extracting elements of interest
    """
    
    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Initialize HTML parser"""
        super().__init__(chunk_size)
        # Import HTML parser lazily to avoid dependency issues
        try:
            from html.parser import HTMLParser
            self.html_parser_available = True
        except ImportError:
            self.html_parser_available = False
            logger.warning("html.parser not available")
    
    def parse_stream(self, stream: BinaryIO) -> Generator[Dict, None, None]:
        """Parse HTML stream in chunks"""
        if not self.html_parser_available:
            # Fall back to regex-based extraction if html.parser is not available
            return self._parse_with_regex(stream)
        
        # Use Python's HTMLParser for proper HTML parsing
        from html.parser import HTMLParser
        
        class ChunkingHTMLParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.current_elements = []
                self.in_script = False
                
            def handle_starttag(self, tag, attrs):
                if tag == 'script':
                    self.in_script = True
                attr_dict = dict(attrs) if attrs else {}
                self.current_elements.append({
                    'type': 'start',
                    'tag': tag,
                    'attrs': attr_dict
                })
                
            def handle_endtag(self, tag):
                if tag == 'script':
                    self.in_script = False
                self.current_elements.append({
                    'type': 'end',
                    'tag': tag
                })
                
            def handle_data(self, data):
                if not self.in_script and data.strip():
                    self.current_elements.append({
                        'type': 'data',
                        'data': data.strip()
                    })
                    
            def get_elements(self):
                """Get and clear current elements"""
                elements = self.current_elements
                self.current_elements = []
                return elements
        
        parser = ChunkingHTMLParser()
        buffer = b""
        
        while True:
            chunk = stream.read(self.chunk_size)
            if not chunk:
                # Process final buffer
                if buffer:
                    try:
                        parser.feed(buffer.decode('utf-8', errors='replace'))
                        elements = parser.get_elements()
                        if elements:
                            yield {'elements': elements}
                    except Exception as e:
                        logger.error(f"Error parsing final HTML chunk: {e}")
                break
                
            buffer += chunk
            
            # Process buffer in chunks
            try:
                parser.feed(buffer.decode('utf-8', errors='replace'))
                elements = parser.get_elements()
                if elements:
                    yield {'elements': elements}
                    
                # Clear buffer as we've processed it
                buffer = b""
            except Exception as e:
                # If parsing fails, we might have an incomplete HTML tag
                # Keep in buffer and try again with more data
                logger.debug(f"HTML parsing incomplete, waiting for more data: {e}")
    
    def _parse_with_regex(self, stream: BinaryIO) -> Generator[Dict, None, None]:
        """Fallback method using regex for HTML parsing when html.parser is not available"""
        # Simple regex patterns for basic HTML elements
        patterns = {
            'links': re.compile(r'<a[^>]+href=["\'](.*?)["\']', re.IGNORECASE),
            'images': re.compile(r'<img[^>]+src=["\'](.*?)["\']', re.IGNORECASE),
            'scripts': re.compile(r'<script[^>]*?>(.*?)</script>', re.IGNORECASE | re.DOTALL),
            'forms': re.compile(r'<form[^>]*?>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        }
        
        text_parser = StreamingTextParser(patterns, self.chunk_size)
        return text_parser.parse_stream(stream)

class StreamingImageProcessor(StreamingParser):
    """
    Process image data in chunks to extract metadata without loading
    the entire image into memory
    """
    
    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Initialize image processor"""
        super().__init__(chunk_size)
    
    def parse_stream(self, stream: BinaryIO) -> Generator[Dict, None, None]:
        """
        Process image streams to extract format and basic metadata
        without loading entire image into memory
        """
        # Read first chunk to identify image format
        header = stream.read(24)  # Read enough bytes to identify common image formats
        if not header:
            return
            
        # Get image format from magic bytes
        image_format = self._identify_image_format(header)
        if not image_format:
            # Return empty result for unrecognized format
            yield {'format': 'unknown'}
            return
            
        # Extract basic metadata
        metadata = {'format': image_format}
        
        if image_format == 'jpeg':
            # Process JPEG chunks looking for metadata
            yield from self._process_jpeg(stream, header)
        elif image_format == 'png':
            # Process PNG chunks
            yield from self._process_png(stream, header)
        else:
            # For other formats, just return the format
            yield metadata
    
    def _identify_image_format(self, header: bytes) -> Optional[str]:
        """Identify image format from header bytes"""
        if header.startswith(b'\xff\xd8\xff'):
            return 'jpeg'
        elif header.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'png'
        elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
            return 'gif'
        elif header.startswith(b'RIFF') and header[8:12] == b'WEBP':
            return 'webp'
        elif header.startswith(b'BM'):
            return 'bmp'
        else:
            return None
    
    def _process_jpeg(self, stream: BinaryIO, header: bytes) -> Generator[Dict, None, None]:
        """Process JPEG image in chunks"""
        # Reset to beginning and process chunks
        stream.seek(0)
        
        metadata = {
            'format': 'jpeg',
            'dimensions': None
        }
        
        # Buffer for incomplete markers
        buffer = b''
        
        while True:
            chunk = stream.read(self.chunk_size)
            if not chunk and not buffer:
                break
                
            buffer += chunk
            
            # Look for SOF (Start of Frame) markers which contain dimensions
            # SOF markers: 0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF
            sof_markers = [b'\xff\xc0', b'\xff\xc1', b'\xff\xc2', b'\xff\xc3', 
                         b'\xff\xc5', b'\xff\xc6', b'\xff\xc7', b'\xff\xc9', 
                         b'\xff\xca', b'\xff\xcb', b'\xff\xcd', b'\xff\xce', b'\xff\xcf']
            
            for marker in sof_markers:
                pos = buffer.find(marker)
                if pos >= 0 and pos + 9 < len(buffer):
                    # Extract height and width from SOF marker
                    height = (buffer[pos+5] << 8) + buffer[pos+6]
                    width = (buffer[pos+7] << 8) + buffer[pos+8]
                    metadata['dimensions'] = (width, height)
                    yield metadata
                    return
            
            # Keep only the last few bytes for marker detection
            if not chunk:  # End of stream
                break
            buffer = buffer[-20:]  # Keep potential markers
        
        # If we couldn't find dimensions, return what we have
        yield metadata
    
    def _process_png(self, stream: BinaryIO, header: bytes) -> Generator[Dict, None, None]:
        """Process PNG image in chunks"""
        # Reset to beginning
        stream.seek(0)
        
        # Skip the PNG signature
        stream.read(8)
        
        metadata = {
            'format': 'png',
            'dimensions': None,
            'chunks': []
        }
        
        # Read chunks
        while True:
            # Read chunk length and type
            chunk_header = stream.read(8)
            if not chunk_header or len(chunk_header) < 8:
                break
                
            length = int.from_bytes(chunk_header[:4], byteorder='big')
            chunk_type = chunk_header[4:8].decode('ascii', errors='replace')
            
            # Add chunk type to metadata
            metadata['chunks'].append(chunk_type)
            
            # Extract dimensions from IHDR chunk
            if chunk_type == 'IHDR' and length >= 8:
                ihdr_data = stream.read(8)  # Read width and height
                if len(ihdr_data) == 8:
                    width = int.from_bytes(ihdr_data[:4], byteorder='big')
                    height = int.from_bytes(ihdr_data[4:8], byteorder='big')
                    metadata['dimensions'] = (width, height)
                    
                    # Skip the rest of the IHDR chunk and its CRC
                    stream.seek(length - 8 + 4, os.SEEK_CUR)
                else:
                    # Skip chunk data and CRC if we couldn't read dimensions
                    stream.seek(length + 4, os.SEEK_CUR)
            else:
                # Skip chunk data and CRC
                stream.seek(length + 4, os.SEEK_CUR)
            
            # If we've found the dimensions, we can return
            if metadata['dimensions']:
                yield metadata
                return
        
        # If we couldn't find dimensions, return what we have
        yield metadata

class StreamingWebSocketFrameParser(StreamingParser):
    """
    Parse WebSocket frames in chunks without loading entire messages into memory
    """
    
    def __init__(self, 
                 chunk_size: int = DEFAULT_CHUNK_SIZE, 
                 max_frame_size: int = 1024 * 1024):
        """
        Initialize WebSocket frame parser
        
        Args:
            chunk_size: Size of chunks to process
            max_frame_size: Maximum size of a WebSocket frame to process
        """
        super().__init__(chunk_size)
        self.max_frame_size = max_frame_size
        self.buffer = b''
        
    def parse_stream(self, stream: BinaryIO) -> Generator[Dict, None, None]:
        """
        Parse WebSocket frames from a stream
        
        Yields:
            Dictionary containing frame information
        """
        while True:
            chunk = stream.read(self.chunk_size)
            if not chunk and not self.buffer:
                break
                
            self.buffer += chunk
            
            # Process complete frames
            while len(self.buffer) >= 2:  # Minimum WebSocket frame header size
                # Parse the frame header
                if len(self.buffer) < 2:
                    break
                    
                # Get first two bytes which contain control bits and payload length
                b1, b2 = self.buffer[0], self.buffer[1]
                
                fin = (b1 & 0x80) != 0
                opcode = b1 & 0x0F
                has_mask = (b2 & 0x80) != 0
                payload_length = b2 & 0x7F
                
                # Determine header size
                header_size = 2
                if payload_length == 126:
                    header_size += 2
                    if len(self.buffer) < 4:
                        break  # Need more data
                    payload_length = int.from_bytes(self.buffer[2:4], byteorder='big')
                elif payload_length == 127:
                    header_size += 8
                    if len(self.buffer) < 10:
                        break  # Need more data
                    payload_length = int.from_bytes(self.buffer[2:10], byteorder='big')
                
                # Add mask bytes to header size if present
                if has_mask:
                    header_size += 4
                
                # Check if we have a complete frame
                if len(self.buffer) < header_size + payload_length:
                    break  # Need more data
                
                # Safety check for unreasonably large frames
                if payload_length > self.max_frame_size:
                    logger.warning(f"WebSocket frame too large: {payload_length} bytes")
                    # Skip this frame
                    self.buffer = self.buffer[header_size + payload_length:]
                    continue
                    
                # Extract mask if present
                mask = None
                if has_mask:
                    mask_start = header_size - 4
                    mask = self.buffer[mask_start:mask_start + 4]
                
                # Extract payload
                payload_start = header_size
                payload_end = payload_start + payload_length
                payload = self.buffer[payload_start:payload_end]
                
                # Apply mask if present
                if has_mask and mask:
                    payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
                
                # Process frame
                frame = {
                    'fin': fin,
                    'opcode': opcode,
                    'length': payload_length
                }
                
                # Interpret the opcode
                if opcode == 0x1:  # Text
                    frame['type'] = 'text'
                    try:
                        frame['text'] = payload.decode('utf-8', errors='replace')
                    except Exception as e:
                        logger.error(f"Error decoding WebSocket text frame: {e}")
                        frame['text'] = None
                elif opcode == 0x2:  # Binary
                    frame['type'] = 'binary'
                    # Don't include full binary data to avoid memory issues
                    frame['data_size'] = len(payload)
                elif opcode == 0x8:  # Close
                    frame['type'] = 'close'
                    if payload_length >= 2:
                        frame['close_code'] = int.from_bytes(payload[:2], byteorder='big')
                        try:
                            frame['close_reason'] = payload[2:].decode('utf-8', errors='replace')
                        except:
                            frame['close_reason'] = None
                elif opcode == 0x9:  # Ping
                    frame['type'] = 'ping'
                elif opcode == 0xA:  # Pong
                    frame['type'] = 'pong'
                else:
                    frame['type'] = f'unknown-{opcode}'
                
                # Yield the frame data
                yield frame
                
                # Remove processed data from buffer
                self.buffer = self.buffer[payload_end:]
            
            # If no more chunks and we can't process what's in the buffer, we're done
            if not chunk:
                break

def create_parser_for_content_type(content_type: str) -> StreamingParser:
    """
    Factory function to create appropriate streaming parser based on content type
    
    Args:
        content_type: MIME type of content
        
    Returns:
        Appropriate StreamingParser instance
    """
    content_type = content_type.lower()
    
    if content_type.startswith('application/json'):
        return StreamingJSONParser()
    elif content_type.startswith('text/html'):
        return StreamingHTMLParser()
    elif content_type.startswith('text/'):
        # Create parser with pre-compiled patterns for text content
        # Import patterns from network_monitor.py
        from network_monitor import (
            EMAIL_PATTERN, PHONE_PATTERN, SSN_PATTERN, CREDIT_CARD_PATTERN,
            IP_ADDRESS_PATTERN, ADDRESS_PATTERN, ZIP_CODE_PATTERN,
            DATE_OF_BIRTH_PATTERN, API_KEY_PATTERN, PASSWORD_PATTERN, JWT_PATTERN
        )
        
        patterns = {
            'email': EMAIL_PATTERN,
            'phone': PHONE_PATTERN,
            'ssn': SSN_PATTERN,
            'credit_card': CREDIT_CARD_PATTERN,
            'ip_address': IP_ADDRESS_PATTERN,
            'address': ADDRESS_PATTERN,
            'zip_code': ZIP_CODE_PATTERN,
            'date_of_birth': DATE_OF_BIRTH_PATTERN,
            'api_key': API_KEY_PATTERN,
            'password': PASSWORD_PATTERN,
            'jwt': JWT_PATTERN
        }
        
        return StreamingTextParser(patterns)
    elif content_type.startswith(('image/', 'application/octet-stream')):
        return StreamingImageProcessor()
    else:
        # Default to text parser for unknown content types
        return StreamingTextParser({})

# Asynchronous stream processing function
async def process_stream_async(stream: BinaryIO, content_type: str) -> Dict:
    """
    Process a stream asynchronously using the appropriate parser
    
    Args:
        stream: Binary stream to process
        content_type: MIME type of content
        
    Returns:
        Dictionary with processing results
    """
    parser = create_parser_for_content_type(content_type)
    results = {'content_type': content_type, 'matches': {}}
    
    async for chunk_result in parser.parse_stream_async(stream):
        # Merge results from chunk
        if isinstance(chunk_result, dict):
            for key, value in chunk_result.items():
                if key not in results:
                    results[key] = value
                elif isinstance(results[key], list) and isinstance(value, list):
                    results[key].extend(value)
                elif isinstance(results[key], dict) and isinstance(value, dict):
                    results[key].update(value)
        
        # Allow other async tasks to run
        await asyncio.sleep(0)
    
    return results

# Demo/test function
def main():
    """Test the streaming parsers with sample data"""
    import tempfile
    import sys
    
    print("Testing streaming parsers...")
    
    # Create sample data
    samples = [
        {
            "content_type": "application/json",
            "data": b'{"items": [{"id": 1, "name": "Test 1", "email": "test1@example.com"}, '
                   b'{"id": 2, "name": "Test 2", "email": "test2@example.com"}]}'
        },
        {
            "content_type": "text/plain",
            "data": b"Here is some text with PII: test@example.com and phone number 555-123-4567 "
                   b"and credit card 4111-1111-1111-1111 and SSN 123-45-6789."
        },
        {
            "content_type": "text/html",
            "data": b"<html><body><h1>Test</h1><p>Email: test@example.com</p>"
                   b"<form><input name='credit_card' value='4111-1111-1111-1111'></form></body></html>"
        }
    ]
    
    for sample in samples:
        print(f"\nTesting {sample['content_type']}:")
        
        # Create temporary file with sample data
        with tempfile.TemporaryFile() as f:
            f.write(sample['data'])
            f.seek(0)
            
            # Create parser
            parser = create_parser_for_content_type(sample['content_type'])
            
            # Process stream
            print("Results:")
            for result in parser.parse_stream(f):
                print(f"  {result}")

if __name__ == "__main__":
    main()