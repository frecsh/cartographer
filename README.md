# Cartographer

A sophisticated network traffic monitoring and analysis tool with advanced MITM proxy capabilities.

## Overview

Cartographer is a network traffic analysis tool designed to intercept, analyze, and visualize HTTP/HTTPS traffic. It uses a Man-in-the-Middle (MITM) proxy to capture network requests and responses, detect sensitive information (PII), and provide a user-friendly interface for reviewing captured traffic.

## Key Features

- **HTTP/HTTPS Traffic Interception**: Captures all web traffic using a MITM proxy
- **WebSocket Support**: Intercepts and analyzes WebSocket communications
- **Binary Content Capture**: Captures and displays images and other binary content
- **PII Detection**: Automatically detects personally identifiable information in traffic
- **Interactive Viewer**: Web-based interface for exploring captured network traffic
- **Caching System**: Efficient caching mechanism to avoid duplicating content
- **Real-time Monitoring**: Live updates of traffic statistics and alerts

## Recent Enhancements

- Added binary content capture for images and other media
- Improved WebSocket message handling and display
- Enhanced viewer.html to properly display various content types including images
- Implemented better content-type detection for accurate processing
- Added efficient base64 encoding for binary data display

## Project Structure

```
cartographer/
├── mitm_proxy.py       # Core proxy implementation with traffic interception
├── network_monitor.py  # PII detection and content analysis functionality
├── captures/           # Directory for storing captured traffic
│   ├── viewer.html     # Web interface for visualizing captured traffic
│   └── cache/          # Cache directory for deduplicated content
├── LICENSE             # MIT License
├── .gitignore          # Git ignore file
└── README.md           # This file
```

## Getting Started

### Prerequisites

- Python 3.7+
- mitmproxy library
- Required Python packages (specified in requirements.txt)

### Running Cartographer

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Start the proxy:
   ```
   python mitm_proxy.py
   ```

3. Configure your browser/device to use the proxy (default: 127.0.0.1:8080)

4. Open the viewer in your browser:
   ```
   file:///path/to/cartographer/captures/viewer.html
   ```

## Configuration Options

Cartographer can be configured using environment variables:

- `CAPTURE_BINARY`: Set to "1" to capture binary content (default: "1")
- `MAX_BINARY_SIZE`: Maximum size in bytes for binary content capture (default: 1048576)
- `BINARY_TYPES`: Comma-separated list of binary content types to capture (default: "image/,audio/,video/")
- `DISPLAY_CONTENT`: Set to "1" to display content in console output (default: "0")
- `FILTER_CONTENT_TYPES`: Comma-separated list of content types to include
- `EXCLUDE_CONTENT_TYPES`: Comma-separated list of content types to exclude

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
