#!/usr/bin/env python3
"""
Backward Compatibility Wrapper
------------------------------
DirectoryHunterAutoscaler has evolved into the unified ReconAutoscaler in tools/autoscaler.py.
This shim provides backwards compatibility for any legacy callers or imports.
"""

from autoscaler import (
    ReconAutoscaler as DirectoryHunterAutoscaler,
    ReconAutoscaler,
    DockerUnixClient,
    SystemResourceMonitor,
    discover_docker_socket
)

if __name__ == "__main__":
    import asyncio
    autoscaler = ReconAutoscaler()
    asyncio.run(autoscaler.run())
