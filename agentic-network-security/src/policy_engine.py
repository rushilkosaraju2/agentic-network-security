# src/policy_engine.py
import json
import ipaddress
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Enforces security policies and constraints"""

    def __init__(self, config_path: str = 'config/policies.json'):
        with open(config_path, 'r') as f:
            self.policies = json.load(f)

        self.severity_thresholds = self.policies['severity_thresholds']
        self.protected_networks = [
            ipaddress.ip_network(net)
            for net in self.policies['protected_ips']
        ]
        self.whitelisted_ips = set(self.policies['whitelisted_ips'])

        logger.info("Policy engine initialized")

    def get_allowed_actions(self, severity: str, confidence: float) -> List[str]:
        """Get allowed actions based on severity and confidence"""
        # Validate inputs
        if not isinstance(severity, str) or not isinstance(confidence, (int, float)):
            logger.warning(f"Invalid types for severity/confidence: {type(severity)}/{type(confidence)}")
            return ['monitor']
        
        # Clamp confidence to 0-1 range
        confidence = max(0, min(1, float(confidence)))
        
        if severity not in self.severity_thresholds:
            logger.warning(f"Unknown severity level: {severity}, defaulting to 'monitor'")
            return ['monitor']

        threshold_config = self.severity_thresholds[severity]
        min_confidence = threshold_config.get('min_confidence', 0.5)

        if confidence >= min_confidence:
            allowed = threshold_config.get('allowed_actions', ['monitor'])
            return allowed if isinstance(allowed, list) else [allowed]
        else:
            # Confidence too low - downgrade to monitoring
            logger.debug(f"Confidence {confidence:.2f} below threshold {min_confidence} for {severity}")
            return ['monitor', 'alert']

    def is_protected_ip(self, ip: str) -> bool:
        """Check if IP is in protected range (internal network)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.protected_networks:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return False

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        return ip in self.whitelisted_ips

    def validate_action(self, action: str, threat: Dict) -> bool:
        """Validate if action is allowed for given threat"""
        try:
            # Validate required threat fields
            if 'severity' not in threat or 'source_ip' not in threat:
                logger.warning(f"Threat missing required fields")
                return False
            
            allowed_actions = self.get_allowed_actions(
                threat['severity'],
                threat.get('confidence', 0)
            )

            if action not in allowed_actions:
                logger.warning(
                    f"Action '{action}' not allowed for severity '{threat['severity']}'")
                return False

            # Prevent blocking of protected IPs
            if action == 'block' and self.is_protected_ip(threat['source_ip']):
                logger.warning(f"Cannot block protected IP: {threat['source_ip']}")
                return False
            
            # Prevent blocking of whitelisted IPs
            if action == 'block' and self.is_whitelisted(threat['source_ip']):
                logger.warning(f"Cannot block whitelisted IP: {threat['source_ip']}")
                return False

            return True
        except Exception as e:
            logger.error(f"Error validating action: {e}")
            return False
