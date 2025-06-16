"""
Addon to track and display network latency statistics, specifically focusing on intercept overhead for both request and response.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Tuple

from mitmproxy import ctx
from mitmproxy import flowfilter
from mitmproxy.flow import Flow


class LatencyStats:
    def __init__(self):
        self.flow_times: Dict[str, Dict[str, float]] = {}
        self.request_intercept_overhead: Dict[str, List[float]] = defaultdict(list)
        self.response_intercept_overhead: Dict[str, List[float]] = defaultdict(list)
        self.total_requests = 0
        self.total_request_intercept_time = 0.0
        self.total_response_intercept_time = 0.0

    def request(self, flow: Flow) -> None:
        """Record the time when request arrives at proxy."""
        self.flow_times[flow.id] = {
            "request_arrival": time.time()
        }
        self.total_requests += 1

    def requestheaders(self, flow: Flow) -> None:
        """Record the time when request intercept starts."""
        if flow.id in self.flow_times:
            self.flow_times[flow.id]["request_intercept_start"] = time.time()

    def request(self, flow: Flow) -> None:
        """Record the time when request intercept ends and request is sent to server."""
        if flow.id in self.flow_times:
            self.flow_times[flow.id]["request_intercept_end"] = time.time()
            
            # Calculate request intercept overhead
            intercept_start = self.flow_times[flow.id].get("request_intercept_start")
            if intercept_start:
                intercept_time = self.flow_times[flow.id]["request_intercept_end"] - intercept_start
                host = flow.request.host
                self.request_intercept_overhead[host].append(intercept_time)
                self.total_request_intercept_time += intercept_time
                
                # Log the request intercept overhead
                ctx.log.info(f"Request intercept overhead for {host}: {intercept_time:.3f} seconds")

    def responseheaders(self, flow: Flow) -> None:
        """Record the time when response intercept starts."""
        if flow.id in self.flow_times:
            self.flow_times[flow.id]["response_intercept_start"] = time.time()

    def response(self, flow: Flow) -> None:
        """Record the time when response intercept ends and response is sent to client."""
        if flow.id in self.flow_times:
            self.flow_times[flow.id]["response_intercept_end"] = time.time()
            
            # Calculate response intercept overhead
            intercept_start = self.flow_times[flow.id].get("response_intercept_start")
            if intercept_start:
                intercept_time = self.flow_times[flow.id]["response_intercept_end"] - intercept_start
                host = flow.request.host
                self.response_intercept_overhead[host].append(intercept_time)
                self.total_response_intercept_time += intercept_time
                
                # Log the response intercept overhead
                ctx.log.info(f"Response intercept overhead for {host}: {intercept_time:.3f} seconds")
            
            # Clean up flow timing data
            del self.flow_times[flow.id]

    def get_stats(self) -> Dict:
        """Get current intercept overhead statistics for both request and response."""
        stats = {
            "total_requests": self.total_requests,
            "request_intercept": {
                "total_time": self.total_request_intercept_time,
                "average_time": self.total_request_intercept_time / self.total_requests if self.total_requests > 0 else 0,
            },
            "response_intercept": {
                "total_time": self.total_response_intercept_time,
                "average_time": self.total_response_intercept_time / self.total_requests if self.total_requests > 0 else 0,
            },
            "total_intercept_time": self.total_request_intercept_time + self.total_response_intercept_time,
            "host_stats": {}
        }
        
        # Combine request and response stats for each host
        all_hosts = set(self.request_intercept_overhead.keys()) | set(self.response_intercept_overhead.keys())
        for host in all_hosts:
            request_overheads = self.request_intercept_overhead.get(host, [])
            response_overheads = self.response_intercept_overhead.get(host, [])
            
            if request_overheads or response_overheads:
                stats["host_stats"][host] = {
                    "requests": len(request_overheads),
                    "request_intercept": {
                        "average_overhead": sum(request_overheads) / len(request_overheads) if request_overheads else 0,
                        "min_overhead": min(request_overheads) if request_overheads else 0,
                        "max_overhead": max(request_overheads) if request_overheads else 0,
                    },
                    "response_intercept": {
                        "average_overhead": sum(response_overheads) / len(response_overheads) if response_overheads else 0,
                        "min_overhead": min(response_overheads) if response_overheads else 0,
                        "max_overhead": max(response_overheads) if response_overheads else 0,
                    }
                }
        
        return stats

    def clear(self) -> None:
        """Clear all statistics."""
        self.flow_times.clear()
        self.request_intercept_overhead.clear()
        self.response_intercept_overhead.clear()
        self.total_requests = 0
        self.total_request_intercept_time = 0.0
        self.total_response_intercept_time = 0.0


addons = [
    LatencyStats()
] 