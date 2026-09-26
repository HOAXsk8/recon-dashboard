import os
import time
import shutil
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Cache for CPU delta calculation
_last_cpu_sample = {"idle": 0.0, "total": 0.0, "timestamp": 0.0}

def read_system_vitals() -> Dict[str, Any]:
    """
    Reads real-time system metrics (CPU, RAM, Disk, Sockets, Load Average)
    directly from /proc without requiring external dependencies like psutil.
    """
    global _last_cpu_sample

    # 1. CPU Percent Calculation
    cpu_percent = 0.0
    try:
        with open("/proc/stat", "r") as f:
            first_line = f.readline().strip()
            fields = [float(x) for x in first_line.split()[1:8]]
        
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0.0) # idle + iowait
        total = sum(fields)
        now = time.time()

        if _last_cpu_sample["total"] > 0 and (now - _last_cpu_sample["timestamp"]) < 10.0:
            idle_delta = idle - _last_cpu_sample["idle"]
            total_delta = total - _last_cpu_sample["total"]
            if total_delta > 0:
                cpu_percent = round((1.0 - (idle_delta / total_delta)) * 100.0, 1)
                cpu_percent = max(0.0, min(100.0, cpu_percent))
        else:
            # Fallback quick sample
            time.sleep(0.05)
            with open("/proc/stat", "r") as f2:
                fields2 = [float(x) for x in f2.readline().strip().split()[1:8]]
            idle2 = fields2[3] + (fields2[4] if len(fields2) > 4 else 0.0)
            total2 = sum(fields2)
            d_idle = idle2 - idle
            d_total = total2 - total
            if d_total > 0:
                cpu_percent = round((1.0 - (d_idle / d_total)) * 100.0, 1)
                cpu_percent = max(0.0, min(100.0, cpu_percent))

        _last_cpu_sample = {"idle": idle, "total": total, "timestamp": now}
    except Exception as e:
        logger.debug(f"Error reading CPU percent from /proc/stat: {e}")

    # 2. RAM Usage
    mem_info = {
        "total_mb": 0,
        "used_mb": 0,
        "available_mb": 0,
        "percent": 0.0,
        "swap_total_mb": 0,
        "swap_used_mb": 0,
        "swap_percent": 0.0
    }
    try:
        raw_mem = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    raw_mem[parts[0].strip()] = int(parts[1].split()[0])
        
        total_kb = raw_mem.get("MemTotal", 1)
        avail_kb = raw_mem.get("MemAvailable", raw_mem.get("MemFree", 0))
        used_kb = total_kb - avail_kb
        swap_total_kb = raw_mem.get("SwapTotal", 0)
        swap_free_kb = raw_mem.get("SwapFree", 0)
        swap_used_kb = swap_total_kb - swap_free_kb

        mem_info["total_mb"] = round(total_kb / 1024)
        mem_info["used_mb"] = round(used_kb / 1024)
        mem_info["available_mb"] = round(avail_kb / 1024)
        mem_info["percent"] = round((used_kb / total_kb) * 100.0, 1)

        mem_info["swap_total_mb"] = round(swap_total_kb / 1024)
        mem_info["swap_used_mb"] = round(swap_used_kb / 1024)
        mem_info["swap_percent"] = round((swap_used_kb / swap_total_kb * 100.0), 1) if swap_total_kb > 0 else 0.0
    except Exception as e:
        logger.debug(f"Error reading memory from /proc/meminfo: {e}")

    # 3. Disk Usage
    disk_info = {"total_gb": 0.0, "used_gb": 0.0, "free_gb": 0.0, "percent": 0.0}
    try:
        du = shutil.disk_usage("/")
        disk_info["total_gb"] = round(du.total / (1024**3), 1)
        disk_info["used_gb"] = round(du.used / (1024**3), 1)
        disk_info["free_gb"] = round(du.free / (1024**3), 1)
        disk_info["percent"] = round((du.used / du.total) * 100.0, 1)
    except Exception as e:
        logger.debug(f"Error reading disk usage: {e}")

    # 4. Open Network Sockets
    open_sockets = 0
    try:
        for proto in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"]:
            if os.path.exists(proto):
                with open(proto, "r") as f:
                    open_sockets += max(0, len(f.readlines()) - 1)
    except Exception as e:
        logger.debug(f"Error reading sockets: {e}")

    # 5. Load Average
    load_avg = [0.0, 0.0, 0.0]
    try:
        load_avg = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        pass

    # Safety status assessment
    is_critical = (cpu_percent >= 92.0 or mem_info["percent"] >= 92.0)
    is_warning = (cpu_percent >= 80.0 or mem_info["percent"] >= 80.0 or open_sockets >= 1500)

    status = "Normal"
    if is_critical:
        status = "Critical (Overload Risk)"
    elif is_warning:
        status = "High Load"

    return {
        "status": status,
        "is_warning": is_warning,
        "is_critical": is_critical,
        "cpu_percent": cpu_percent,
        "memory": mem_info,
        "disk": disk_info,
        "open_sockets": open_sockets,
        "load_average": load_avg,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


def estimate_pipeline_footprint(domain_count: int = 1, tools: Optional[list] = None) -> Dict[str, Any]:
    """
    Estimates the projected resource delta of adding a new pipeline scan.
    """
    vitals = read_system_vitals()
    curr_cpu = vitals["cpu_percent"]
    curr_ram = vitals["memory"]["percent"]

    # Estimated marginal consumption per active workspace pipeline
    # Nmap + ffuf + tech fingerprinting consumes approx ~20-25% CPU core share and ~400-600MB RAM
    scale_factor = min(2.0, 1.0 + (max(0, domain_count - 1) * 0.15))
    delta_cpu = round(22.0 * scale_factor, 1)
    delta_ram_mb = round(500.0 * scale_factor)

    total_mb = vitals["memory"]["total_mb"] or 8000
    delta_ram_pct = round((delta_ram_mb / total_mb) * 100.0, 1)

    projected_cpu = min(100.0, round(curr_cpu + delta_cpu, 1))
    projected_ram = min(100.0, round(curr_ram + delta_ram_pct, 1))

    # Warning threshold rules
    warning_reasons = []
    if projected_cpu >= 80.0:
        warning_reasons.append(f"Projected CPU utilization is {projected_cpu}% (elevated load).")
    if projected_ram >= 80.0:
        warning_reasons.append(f"Projected RAM utilization is {projected_ram}% (low remaining buffer).")

    warning_required = bool(warning_reasons)
    critical_risk = (projected_cpu >= 90.0 or projected_ram >= 90.0)

    recommendation = "Safe to run concurrently."
    if critical_risk:
        recommendation = "System resources are near capacity. Starting this pipeline is likely to cause packet drops or trigger the automated circuit breaker."
    elif warning_required:
        recommendation = "System resources will be elevated. Running multiple intensive scans simultaneously may cause slower response times."

    return {
        "current_cpu": curr_cpu,
        "current_ram": curr_ram,
        "delta_cpu": delta_cpu,
        "delta_ram_mb": delta_ram_mb,
        "projected_cpu": projected_cpu,
        "projected_ram": projected_ram,
        "projected_vitals": {
            "projected_cpu_pct": projected_cpu,
            "projected_ram_pct": projected_ram
        },
        "warning_required": warning_required,
        "warning_reasons": warning_reasons,
        "critical_risk": critical_risk,
        "recommendation": recommendation
    }
