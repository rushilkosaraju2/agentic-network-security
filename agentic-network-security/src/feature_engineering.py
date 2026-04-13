# src/feature_engineering.py
import pandas as pd
import numpy as np
from typing import Dict
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract behavioral features from network logs"""

    def __init__(self, time_window: int = 60):
        if time_window <= 0:
            raise ValueError("time_window must be positive")
        self.time_window = time_window

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract all features from log data
        
        Handles edge cases like empty DataFrames, invalid timestamps,
        and division by zero in derived metrics.
        """
        if df.empty:
            logger.warning("Empty DataFrame provided to extract_features")
            return pd.DataFrame()

        try:
            df = df.copy()
            
            # Ensure timestamp is datetime, handle invalid values
            if 'timestamp' not in df.columns:
                logger.error("'timestamp' column not found")
                return pd.DataFrame()
            
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            invalid_ts = df['timestamp'].isna().sum()
            if invalid_ts > 0:
                logger.warning(f"Removing {invalid_ts} rows with invalid timestamps")
                df = df[df['timestamp'].notna()]
            
            if df.empty:
                logger.warning("No valid timestamps after cleanup")
                return pd.DataFrame()

            # Create time windows
            df['time_bin'] = df['timestamp'].dt.floor(f'{self.time_window}s')

            # Group by source IP and time window
            features = df.groupby(['source_ip', 'time_bin']).agg({
                'dest_ip': 'nunique',
                'port': ['nunique', 'count'],
                'bytes': 'sum',
                'protocol': lambda x: x.mode()[0] if len(x) > 0 else 'unknown',
                'failed_login': 'sum',
                'timestamp': ['min', 'max']
            }).reset_index()

            # Flatten column names
            features.columns = [
                'source_ip', 'time_bin',
                'unique_dest_ips', 'unique_ports', 'connection_count',
                'total_bytes', 'primary_protocol', 'failed_logins',
                'window_start', 'window_end'
            ]

            # Calculate connection rate
            features['connection_rate'] = features['connection_count'] / self.time_window

            # Calculate average bytes per connection (handle zero safely)
            features['avg_bytes_per_conn'] = np.where(
                features['connection_count'] > 0,
                features['total_bytes'] / features['connection_count'],
                0
            )

            # Add port diversity metric (handle zero safely)
            features['port_diversity'] = np.where(
                features['connection_count'] > 0,
                features['unique_ports'] / features['connection_count'],
                0
            )

            logger.info(f"Extracted features for {len(features)} IP-window combinations")
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}", exc_info=True)
            return pd.DataFrame()

    def extract_ip_history_features(self, df: pd.DataFrame, ip: str) -> Dict:
        """Extract historical features for a specific IP"""
        try:
            if df.empty or 'source_ip' not in df.columns:
                return {}
            
            ip_data = df[df['source_ip'] == ip]
            if ip_data.empty:
                logger.debug(f"No data found for IP {ip}")
                return {}

            # Ensure timestamp is valid
            if 'timestamp' in ip_data.columns:
                ip_data = ip_data.copy()
                ip_data['timestamp'] = pd.to_datetime(ip_data['timestamp'], errors='coerce')
                ip_data = ip_data[ip_data['timestamp'].notna()]
            
            if ip_data.empty:
                return {}

            features = {
                'first_seen': ip_data['timestamp'].min() if 'timestamp' in ip_data.columns else None,
                'last_seen': ip_data['timestamp'].max() if 'timestamp' in ip_data.columns else None,
                'total_connections': len(ip_data),
                'unique_destinations': ip_data['dest_ip'].nunique() if 'dest_ip' in ip_data.columns else 0,
                'total_bytes': int(ip_data['bytes'].sum()) if 'bytes' in ip_data.columns else 0,
                'protocols_used': ip_data['protocol'].unique().tolist() if 'protocol' in ip_data.columns else [],
                'ports_accessed': sorted(ip_data['port'].unique().tolist()) if 'port' in ip_data.columns else [],
                'total_failed_logins': int(ip_data['failed_login'].sum()) if 'failed_login' in ip_data.columns else 0
            }
            return features
            
        except Exception as e:
            logger.error(f"Error extracting IP history for {ip}: {e}", exc_info=True)
            return {}
