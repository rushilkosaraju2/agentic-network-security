import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class IncidentMemory:
    """Manages persistent storage of incidents and IP history"""

    def __init__(self, db_path: str = 'data/incidents.db'):
        self.db_path = db_path
        self._init_database()

    def get_connection(self):
        """Returns a database connection with row factory enabled"""
        try:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database {self.db_path}: {e}")
            raise

    def _init_database(self):
        """Initialize database schema"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Using threat_type (singular) to match the store_incident logic
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        description TEXT,
                        recommended_action TEXT,
                        is_repeat_offender INTEGER DEFAULT 0,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ip_history (
                        source_ip TEXT PRIMARY KEY,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        incident_count INTEGER DEFAULT 0,
                        total_confidence REAL DEFAULT 0,
                        reputation_score REAL DEFAULT 100,
                        last_action TEXT,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Add multiple indexes for query performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)')
                conn.commit()
                logger.info(f"Database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}", exc_info=True)
            raise

    def store_incident(self, incident: Dict):
        """Stores a new incident and updates IP reputation history using a shared transaction"""
        try:
            # Validate required fields
            if 'source_ip' not in incident:
                logger.error("Incident missing required field: source_ip")
                return
            
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Handle Timestamp conversion
                timestamp = incident.get('timestamp')
                if timestamp is None:
                    timestamp_str = datetime.now().isoformat()
                elif hasattr(timestamp, 'isoformat'):
                    timestamp_str = timestamp.isoformat()
                else:
                    timestamp_str = str(timestamp)

                # Defensive logic to find the threat type name
                threat_name = incident.get('threat_type') or \
                    incident.get('threat_types') or \
                    incident.get('type') or \
                    "Unknown Threat"

                if isinstance(threat_name, list):
                    threat_name = ", ".join(str(t) for t in threat_name)
                
                # Validate confidence
                try:
                    confidence = float(incident.get('confidence', 0))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid confidence value: {incident.get('confidence')}, using 0")
                    confidence = 0

                cursor.execute('''
                    INSERT INTO incidents (
                        timestamp, source_ip, threat_type, severity, 
                        confidence, description, recommended_action, is_repeat_offender
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    timestamp_str,
                    incident.get('source_ip'),
                    threat_name,
                    incident.get('severity', 'medium'),
                    confidence,
                    incident.get('description', 'No description provided'),
                    incident.get('recommended_action') or incident.get('action'),
                    1 if incident.get('is_repeat_offender', False) else 0
                ))

                # PASS THE CURSOR to share the connection and avoid "Database is locked"
                self._update_ip_history(cursor, incident, timestamp_str)

                # Commit once for both operations
                conn.commit()
                logger.info(f"Stored incident for IP {incident['source_ip']}")
        except sqlite3.Error as e:
            logger.error(f"Database error storing incident: {e}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"Unexpected error storing incident: {e}", exc_info=True)

    def _update_ip_history(self, cursor, incident: Dict, timestamp_str: str):
        """Internal helper to update IP reputation using an existing transaction cursor"""
        cursor.execute('SELECT incident_count, total_confidence FROM ip_history WHERE source_ip = ?',
                       (incident['source_ip'],))
        existing = cursor.fetchone()

        if existing:
            count = existing['incident_count'] + 1
            total_conf = existing['total_confidence'] + \
                incident.get('confidence', 0)
            reputation = self._calculate_reputation(count, total_conf / count)

            cursor.execute('''
                UPDATE ip_history
                SET last_seen = ?, incident_count = ?, total_confidence = ?, 
                    reputation_score = ?, last_action = ?, updated_at = ?
                WHERE source_ip = ?
            ''', (
                timestamp_str, count, total_conf, reputation,
                incident.get('recommended_action') or incident.get('action'),
                datetime.now().isoformat(),
                incident['source_ip']
            ))
        else:
            reputation = self._calculate_reputation(
                1, incident.get('confidence', 0))
            cursor.execute('''
                INSERT INTO ip_history (
                    source_ip, first_seen, last_seen, incident_count,
                    total_confidence, reputation_score, last_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident['source_ip'], timestamp_str, timestamp_str,
                1, incident.get('confidence', 0), reputation,
                incident.get('recommended_action') or incident.get('action')
            ))

    def _calculate_reputation(self, incident_count: int, avg_confidence: float) -> float:
        """Calculate reputation score (0-100, lower is worse)"""
        score = 100.0 - (incident_count * 10) - (avg_confidence * 20)
        return max(0, min(100, score))  # Clamp to 0-100

    def get_ip_history(self, source_ip: str) -> List[Dict]:
        """Returns a list of all past incidents for an IP address"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT * FROM incidents WHERE source_ip = ? ORDER BY timestamp DESC', (source_ip,))
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error retrieving IP history for {source_ip}: {e}")
            return []

    def get_statistics(self) -> Dict:
        """Fetch system-wide stats for the final summary"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM incidents')
                total = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM incidents')
                unique = cursor.fetchone()[0]
                
                cursor.execute('SELECT AVG(reputation_score) FROM ip_history')
                avg_reputation = cursor.fetchone()[0] or 100
                
                cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'critical'")
                critical = cursor.fetchone()[0]
                
                return {
                    'total_incidents': total,
                    'unique_ips': unique,
                    'average_reputation': round(avg_reputation, 2),
                    'critical_incidents': critical
                }
        except sqlite3.Error as e:
            logger.error(f"Error retrieving statistics: {e}")
            return {}

    def close(self):
        logger.info("Database handler closed")
