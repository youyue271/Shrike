#!/usr/bin/env python3
"""
ResultServer - receives trace data from guest VM over TCP socket.

Inspired by Cuckoo/CAPE sandbox architecture where guest agent streams
artifacts to host in real-time, preventing malware from destroying them.
"""

import socket
import threading
import json
import logging
import sys
import base64
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class ResultServer:
    def __init__(self, host='192.168.100.1', port=42042, output_dir=None):
        self.host = host
        self.port = port
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / 'artifacts'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.server_socket = None
        self.running = False
        self.clients = []

    def resolve_artifact_path(self, name):
        """Resolve an artifact name under output_dir without allowing traversal."""
        if not name or not isinstance(name, str):
            raise ValueError("artifact name must be a non-empty string")
        candidate = Path(name)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"unsafe artifact name: {name}")
        destination = (self.output_dir / candidate).resolve()
        output_root = self.output_dir.resolve()
        if output_root not in destination.parents and destination != output_root:
            raise ValueError(f"unsafe artifact path: {name}")
        return destination

    def write_artifact_message(self, message):
        """Write a result artifact message sent by the guest runtime."""
        destination = self.resolve_artifact_path(message.get("name"))
        if "content_base64" in message:
            data = base64.b64decode(message.get("content_base64") or "", validate=True)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        else:
            content = message.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        logger.info(f"Wrote artifact: {destination.relative_to(self.output_dir)}")

    def process_json_message(self, line, trace_writer):
        """Process one JSON line. Returns True when it was handled as an artifact."""
        message = json.loads(line)
        if isinstance(message, dict) and message.get("type") == "artifact":
            self.write_artifact_message(message)
            return True

        if trace_writer is not None:
            trace_writer.write(line + "\n")
            trace_writer.flush()
        return False

    def start(self):
        """Start the result server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

        logger.info(f"ResultServer listening on {self.host}:{self.port}")
        logger.info(f"Output directory: {self.output_dir}")

        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"Client connected: {client_address}")

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                self.clients.append((client_socket, client_thread))

            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
                break

    def handle_client(self, client_socket, client_address):
        """Handle a single client connection."""
        client_id = f"{client_address[0]}_{client_address[1]}"
        output_file = self.output_dir / f"trace_{client_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ndjson"

        logger.info(f"Client {client_id}: connected")

        try:
            trace_writer = None
            buffer = b''
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    buffer += data

                    # Process complete lines
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        if line.strip():
                            try:
                                decoded = line.decode('utf-8')
                                handled = self.process_json_message(decoded, trace_writer)
                                if not handled and trace_writer is None:
                                    trace_writer = open(output_file, 'w', encoding='utf-8')
                                    logger.info(f"Client {client_id}: writing trace to {output_file.name}")
                                    trace_writer.write(decoded + '\n')
                                    trace_writer.flush()
                            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                                logger.warning(f"Client {client_id}: invalid JSON line: {e}")
                            except ValueError as e:
                                logger.warning(f"Client {client_id}: rejected artifact message: {e}")

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Client {client_id}: error receiving data: {e}")
                    break

            # Write any remaining data
            if buffer.strip():
                try:
                    decoded = buffer.decode('utf-8')
                    handled = self.process_json_message(decoded, trace_writer)
                    if not handled and trace_writer is None:
                        trace_writer = open(output_file, 'w', encoding='utf-8')
                        logger.info(f"Client {client_id}: writing trace to {output_file.name}")
                        trace_writer.write(decoded + '\n')
                except:
                    pass
            if trace_writer is not None:
                trace_writer.close()

        except Exception as e:
            logger.error(f"Client {client_id}: error handling connection: {e}")

        finally:
            client_socket.close()
            logger.info(f"Client {client_id}: disconnected")

    def stop(self):
        """Stop the result server."""
        logger.info("Stopping ResultServer...")
        self.running = False

        for client_socket, _ in self.clients:
            try:
                client_socket.close()
            except:
                pass

        if self.server_socket:
            self.server_socket.close()

        logger.info("ResultServer stopped")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Shrike ResultServer - receives trace data from guest VM')
    parser.add_argument('--host', default='192.168.100.1', help='Host IP to bind to')
    parser.add_argument('--port', type=int, default=42042, help='Port to listen on')
    parser.add_argument('--output-dir', required=True, help='Directory to write trace files')

    args = parser.parse_args()

    server = ResultServer(host=args.host, port=args.port, output_dir=args.output_dir)

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        server.stop()


if __name__ == '__main__':
    main()
