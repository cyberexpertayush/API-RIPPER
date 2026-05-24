"""
API RIPPER — WebSocket Routes
Real-time scan progress broadcasting with global live feed
"""

import logging
import json
import asyncio
from collections import deque
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.responses import JSONResponse

from backend.scanner.orchestrator import set_broadcast_callback

logger = logging.getLogger(__name__)
router = APIRouter()

# Connected WebSocket clients per scan_id
_clients: Dict[str, Set[WebSocket]] = {}

# Global clients that receive ALL scan broadcasts (for Dashboard live feed)
_global_clients: Set[WebSocket] = set()

# ── Ring buffer for broadcast history ────────────────────────────────────
# Stores the last N messages so reconnecting Dashboard clients see the
# full scan output even after navigating away and coming back.
MAX_BUFFER_SIZE = 1000
_broadcast_buffer: deque = deque(maxlen=MAX_BUFFER_SIZE)

# Track whether any scan is currently active
_active_scan_id: str | None = None
# ─────────────────────────────────────────────────────────────────────────


async def broadcast_to_scan(scan_id: str, data: dict):
    """Broadcast data to all WebSocket clients watching a scan AND global listeners"""
    global _active_scan_id

    # Track active scan and manage buffer lifecycle
    msg_type = data.get("type", "")
    if msg_type == "scan_started":
        # New scan starting — clear buffer for fresh history
        _broadcast_buffer.clear()
        _active_scan_id = scan_id
    elif msg_type == "scan_complete":
        _active_scan_id = None

    # Store in ring buffer (with scan_id attached)
    buffered_msg = {**data, "scan_id": scan_id}
    _broadcast_buffer.append(buffered_msg)

    # Send to scan-specific subscribers
    clients = _clients.get(scan_id, set())
    dead = set()
    for ws in clients:
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    # Remove dead connections
    _clients[scan_id] = clients - dead

    # Also send to global listeners (Dashboard live feed)
    global_dead = set()
    for ws in _global_clients:
        try:
            await ws.send_json(buffered_msg)
        except Exception:
            global_dead.add(ws)
    _global_clients.difference_update(global_dead)


# Register broadcast callback with orchestrator
set_broadcast_callback(broadcast_to_scan)


@router.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress (scan-specific)"""
    await websocket.accept()

    # Register client
    if scan_id not in _clients:
        _clients[scan_id] = set()
    _clients[scan_id].add(websocket)

    logger.info(f"WebSocket client connected for scan: {scan_id}")

    try:
        while True:
            # Keep connection alive, wait for client messages
            data = await websocket.receive_text()
            # Echo or handle client ping
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from scan: {scan_id}")
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        _clients.get(scan_id, set()).discard(websocket)
        if scan_id in _clients and not _clients[scan_id]:
            del _clients[scan_id]


@router.websocket("/ws/live")
async def live_feed_websocket(websocket: WebSocket):
    """Global WebSocket for Dashboard live scan feed — receives ALL scan broadcasts"""
    await websocket.accept()

    # ── Replay buffered history to the newly connected client ────────
    # This ensures switching tabs and coming back doesn't lose output
    if _broadcast_buffer:
        logger.info(f"Replaying {len(_broadcast_buffer)} buffered messages to new client")
        for msg in _broadcast_buffer:
            try:
                await websocket.send_json(msg)
            except Exception:
                # Client disconnected during replay
                return
        # Small yield to flush all replayed messages
        await asyncio.sleep(0.01)
    # ─────────────────────────────────────────────────────────────────

    _global_clients.add(websocket)
    logger.info("Dashboard live feed client connected")

    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong", "status": "healthy"})
    except WebSocketDisconnect:
        logger.info("Dashboard live feed client disconnected")
    except Exception:
        pass
    finally:
        _global_clients.discard(websocket)


@router.websocket("/ws/status")
async def status_websocket(websocket: WebSocket):
    """General WebSocket for system status updates"""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong", "status": "healthy"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


@router.get("/api/live-buffer")
async def get_live_buffer():
    """Return the current broadcast buffer as JSON for Dashboard hydration.
    Called on Dashboard mount to restore full scan history."""
    return JSONResponse(content=list(_broadcast_buffer))
