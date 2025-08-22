#!/usr/bin/env python3

import os
import sys
import time
import psutil
import syslog
import json
from datetime import datetime

class HostCfgdMonitor:
    def __init__(self):
        self.process_name = "hostcfgd"
        self.cpu_threshold = 80.0  # CPU usage threshold in percentage
        self.memory_threshold = 500 * 1024 * 1024  # Memory threshold in bytes (500MB)
        self.check_interval = 30  # Check interval in seconds
        self.log_file = "/var/log/hostcfgd_monitor.log"
        
    def find_hostcfgd_process(self):
        """Find the hostcfgd process by name"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] == 'python3' and proc.info['cmdline']:
                    cmdline = ' '.join(proc.info['cmdline'])
                    if 'hostcfgd' in cmdline:
                        return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None
    
    def get_process_stats(self, proc):
        """Get CPU and memory statistics for the process"""
        try:
            cpu_percent = proc.cpu_percent(interval=1.0)
            memory_info = proc.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            
            return {
                'pid': proc.pid,
                'cpu_percent': cpu_percent,
                'memory_mb': memory_mb,
                'memory_bytes': memory_info.rss,
                'status': proc.status(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            syslog.syslog(syslog.LOG_ERR, f"Error getting process stats: {e}")
            return None
    
    def log_stats(self, stats):
        """Log the statistics to syslog and file"""
        if not stats:
            return
            
        log_msg = (f"hostcfgd_monitor: PID={stats['pid']}, "
                  f"CPU={stats['cpu_percent']:.2f}%, "
                  f"Memory={stats['memory_mb']:.2f}MB, "
                  f"Status={stats['status']}")
        
        syslog.syslog(syslog.LOG_INFO, log_msg)
        
        # Log to file with timestamp
        try:
            with open(self.log_file, 'a') as f:
                timestamp = datetime.now().isoformat()
                f.write(f"{timestamp}: {log_msg}\n")
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Error writing to log file: {e}")
    
    def check_thresholds(self, stats):
        """Check if process exceeds thresholds and take action"""
        if not stats:
            return
            
        alerts = []
        
        if stats['cpu_percent'] > self.cpu_threshold:
            alerts.append(f"CPU usage {stats['cpu_percent']:.2f}% exceeds threshold {self.cpu_threshold}%")
            
        if stats['memory_bytes'] > self.memory_threshold:
            alerts.append(f"Memory usage {stats['memory_mb']:.2f}MB exceeds threshold {self.memory_threshold/(1024*1024):.2f}MB")
        
        if alerts:
            alert_msg = f"hostcfgd_monitor ALERT: {'; '.join(alerts)}"
            syslog.syslog(syslog.LOG_ERR, alert_msg)
            
            # You could add additional actions here like:
            # - Sending notifications
            # - Restarting the service
            # - Collecting diagnostic information
    
    def run(self):
        """Main monitoring loop"""
        syslog.syslog(syslog.LOG_INFO, "hostcfgd_monitor: Starting monitoring daemon")
        
        while True:
            try:
                proc = self.find_hostcfgd_process()
                
                if proc:
                    stats = self.get_process_stats(proc)
                    self.log_stats(stats)
                    self.check_thresholds(stats)
                else:
                    syslog.syslog(syslog.LOG_WARNING, "hostcfgd_monitor: hostcfgd process not found")
                
                time.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                syslog.syslog(syslog.LOG_INFO, "hostcfgd_monitor: Stopping monitoring daemon")
                break
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR, f"hostcfgd_monitor: Unexpected error: {e}")
                time.sleep(self.check_interval)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--status':
        # Quick status check
        monitor = HostCfgdMonitor()
        proc = monitor.find_hostcfgd_process()
        if proc:
            stats = monitor.get_process_stats(proc)
            if stats:
                print(json.dumps(stats, indent=2))
            else:
                print("Error getting process statistics")
        else:
            print("hostcfgd process not found")
    else:
        # Run as daemon
        monitor = HostCfgdMonitor()
        monitor.run()

if __name__ == "__main__":
    main()
