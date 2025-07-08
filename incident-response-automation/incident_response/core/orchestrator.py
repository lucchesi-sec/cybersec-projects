"""
Incident Response Orchestrator

Main coordination engine for automated incident response operations.
Follows NIST Cybersecurity Framework and SANS incident response methodology.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import uuid

from .detector import ThreatDetector
from .analyzer import IncidentAnalyzer  
from .responder import AutomatedResponder
from ..models.incident import Incident, IncidentSeverity, IncidentStatus
from ..utils.logging import setup_audit_logging
from ..utils.metrics import MetricsCollector


class OrchestrationMode(Enum):
    """Orchestration operating modes."""
    MONITORING = "monitoring"
    DETECTION = "detection"
    ANALYSIS = "analysis"
    RESPONSE = "response"
    RECOVERY = "recovery"


@dataclass
class OrchestrationConfig:
    """Configuration for incident response orchestration."""
    
    # Detection settings
    detection_interval: int = 60  # seconds
    detection_enabled: bool = True
    auto_analyze: bool = True
    
    # Analysis settings
    analysis_timeout: int = 300  # seconds
    threat_intel_timeout: int = 60
    evidence_collection_enabled: bool = True
    
    # Response settings
    auto_response_enabled: bool = False
    max_response_time: int = 900  # 15 minutes
    require_human_approval: bool = True
    
    # Escalation settings
    escalation_thresholds: Dict[str, int] = field(default_factory=lambda: {
        'critical': 300,    # 5 minutes
        'high': 900,        # 15 minutes  
        'medium': 3600,     # 1 hour
        'low': 86400        # 24 hours
    })
    
    # Integration settings
    siem_integration: bool = True
    threat_intel_integration: bool = True
    communication_channels: List[str] = field(default_factory=lambda: ['email', 'slack'])
    
    # Compliance settings
    compliance_frameworks: List[str] = field(default_factory=lambda: ['nist', 'sans'])
    audit_logging: bool = True
    evidence_retention_days: int = 2555  # 7 years


class IncidentOrchestrator:
    """
    Main orchestration engine for automated incident response.
    
    Coordinates detection, analysis, response, and recovery phases
    according to industry-standard incident response frameworks.
    """
    
    def __init__(self, config: OrchestrationConfig):
        """Initialize orchestrator with configuration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.detector = ThreatDetector()
        self.analyzer = IncidentAnalyzer()
        self.responder = AutomatedResponder()
        
        # State management
        self.active_incidents: Dict[str, Incident] = {}
        self.detection_tasks: Dict[str, asyncio.Task] = {}
        self.analysis_tasks: Dict[str, asyncio.Task] = {}
        self.response_tasks: Dict[str, asyncio.Task] = {}
        
        # Metrics and monitoring
        self.metrics = MetricsCollector()
        
        # Event callbacks
        self.incident_callbacks: Dict[str, List[Callable]] = {
            'incident_created': [],
            'incident_updated': [],
            'incident_closed': [],
            'escalation_triggered': [],
            'response_completed': []
        }
        
        # Setup audit logging
        if config.audit_logging:
            setup_audit_logging()
        
        self.logger.info("Incident Response Orchestrator initialized")
    
    async def start_monitoring(self):
        """Start continuous monitoring and detection."""
        self.logger.info("Starting incident response monitoring")
        
        try:
            # Start detection loops
            detection_task = asyncio.create_task(self._detection_loop())
            
            # Start incident management loop
            management_task = asyncio.create_task(self._incident_management_loop())
            
            # Start metrics collection
            metrics_task = asyncio.create_task(self._metrics_loop())
            
            # Wait for all tasks
            await asyncio.gather(
                detection_task,
                management_task, 
                metrics_task,
                return_exceptions=True
            )
            
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")
            raise
    
    async def _detection_loop(self):
        """Continuous threat detection loop."""
        while True:
            try:
                if self.config.detection_enabled:
                    # Run detection
                    threats = await self.detector.detect_threats()
                    
                    # Process detected threats
                    for threat in threats:
                        await self._handle_detected_threat(threat)
                    
                    # Update metrics
                    self.metrics.increment('threats_detected', len(threats))
                
                # Wait for next detection cycle
                await asyncio.sleep(self.config.detection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in detection loop: {e}")
                await asyncio.sleep(self.config.detection_interval)
    
    async def _incident_management_loop(self):
        """Continuous incident management and escalation loop."""
        while True:
            try:
                current_time = datetime.now()
                
                # Check for escalations
                for incident_id, incident in self.active_incidents.items():
                    await self._check_escalation(incident, current_time)
                
                # Clean up completed incidents
                await self._cleanup_completed_incidents()
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in incident management loop: {e}")
                await asyncio.sleep(60)
    
    async def _metrics_loop(self):
        """Continuous metrics collection loop."""
        while True:
            try:
                # Collect system metrics
                await self.metrics.collect_system_metrics()
                
                # Collect incident metrics
                await self._collect_incident_metrics()
                
                # Wait before next collection
                await asyncio.sleep(300)  # Every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in metrics loop: {e}")
                await asyncio.sleep(300)
    
    async def _handle_detected_threat(self, threat: Dict[str, Any]):
        """Handle a detected threat by creating and processing incident."""
        try:
            # Create incident from threat
            incident = await self._create_incident_from_threat(threat)
            
            # Add to active incidents
            self.active_incidents[incident.id] = incident
            
            # Trigger callbacks
            await self._trigger_callbacks('incident_created', incident)
            
            # Start automated analysis if enabled
            if self.config.auto_analyze:
                analysis_task = asyncio.create_task(
                    self._analyze_incident(incident)
                )
                self.analysis_tasks[incident.id] = analysis_task
            
            self.logger.info(f"Created incident {incident.id} for threat {threat.get('id')}")
            
        except Exception as e:
            self.logger.error(f"Error handling detected threat: {e}")
    
    async def _create_incident_from_threat(self, threat: Dict[str, Any]) -> Incident:
        """Create incident object from threat detection."""
        incident_id = str(uuid.uuid4())
        
        # Determine initial severity based on threat characteristics
        severity = self._calculate_threat_severity(threat)
        
        incident = Incident(
            id=incident_id,
            title=threat.get('title', f"Security Threat Detected"),
            description=threat.get('description', ''),
            severity=severity,
            status=IncidentStatus.NEW,
            created_at=datetime.now(),
            source_data=threat,
            detected_by='automated_detection',
            category=threat.get('category', 'unknown')
        )
        
        return incident
    
    def _calculate_threat_severity(self, threat: Dict[str, Any]) -> IncidentSeverity:
        """Calculate incident severity based on threat characteristics."""
        score = threat.get('severity_score', 0)
        
        if score >= 9.0:
            return IncidentSeverity.CRITICAL
        elif score >= 7.0:
            return IncidentSeverity.HIGH
        elif score >= 4.0:
            return IncidentSeverity.MEDIUM
        else:
            return IncidentSeverity.LOW
    
    async def _analyze_incident(self, incident: Incident):
        """Perform automated incident analysis."""
        try:
            self.logger.info(f"Starting analysis for incident {incident.id}")
            
            # Update incident status
            incident.status = IncidentStatus.ANALYZING
            await self._trigger_callbacks('incident_updated', incident)
            
            # Perform analysis with timeout
            analysis_result = await asyncio.wait_for(
                self.analyzer.analyze_incident(incident),
                timeout=self.config.analysis_timeout
            )
            
            # Update incident with analysis results
            incident.analysis_results = analysis_result
            incident.analyzed_at = datetime.now()
            
            # Determine if automated response is needed
            if (self.config.auto_response_enabled and 
                analysis_result.get('recommend_auto_response', False) and
                not self.config.require_human_approval):
                
                # Start automated response
                response_task = asyncio.create_task(
                    self._respond_to_incident(incident)
                )
                self.response_tasks[incident.id] = response_task
            else:
                # Mark as requiring human intervention
                incident.status = IncidentStatus.INVESTIGATING
                await self._trigger_callbacks('incident_updated', incident)
            
            self.logger.info(f"Analysis completed for incident {incident.id}")
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Analysis timeout for incident {incident.id}")
            incident.status = IncidentStatus.INVESTIGATING
            incident.analysis_results = {'error': 'Analysis timeout'}
            
        except Exception as e:
            self.logger.error(f"Error analyzing incident {incident.id}: {e}")
            incident.status = IncidentStatus.INVESTIGATING
            incident.analysis_results = {'error': str(e)}
        
        finally:
            # Clean up analysis task
            if incident.id in self.analysis_tasks:
                del self.analysis_tasks[incident.id]
    
    async def _respond_to_incident(self, incident: Incident):
        """Execute automated response to incident."""
        try:
            self.logger.info(f"Starting automated response for incident {incident.id}")
            
            # Update incident status
            incident.status = IncidentStatus.RESPONDING
            await self._trigger_callbacks('incident_updated', incident)
            
            # Execute response actions
            response_result = await asyncio.wait_for(
                self.responder.respond_to_incident(incident),
                timeout=self.config.max_response_time
            )
            
            # Update incident with response results
            incident.response_results = response_result
            incident.response_completed_at = datetime.now()
            
            # Mark as resolved if response was successful
            if response_result.get('success', False):
                incident.status = IncidentStatus.RESOLVED
                incident.resolved_at = datetime.now()
            else:
                incident.status = IncidentStatus.INVESTIGATING
            
            await self._trigger_callbacks('response_completed', incident)
            self.logger.info(f"Automated response completed for incident {incident.id}")
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Response timeout for incident {incident.id}")
            incident.status = IncidentStatus.INVESTIGATING
            incident.response_results = {'error': 'Response timeout'}
            
        except Exception as e:
            self.logger.error(f"Error responding to incident {incident.id}: {e}")
            incident.status = IncidentStatus.INVESTIGATING
            incident.response_results = {'error': str(e)}
        
        finally:
            # Clean up response task
            if incident.id in self.response_tasks:
                del self.response_tasks[incident.id]
    
    async def _check_escalation(self, incident: Incident, current_time: datetime):
        """Check if incident needs escalation based on time thresholds."""
        if incident.status in [IncidentStatus.CLOSED, IncidentStatus.RESOLVED]:
            return
        
        # Calculate time since creation
        time_elapsed = (current_time - incident.created_at).total_seconds()
        
        # Get escalation threshold for incident severity
        threshold = self.config.escalation_thresholds.get(
            incident.severity.value, 3600
        )
        
        # Check if escalation is needed
        if time_elapsed > threshold and not incident.escalated:
            await self._escalate_incident(incident)
    
    async def _escalate_incident(self, incident: Incident):
        """Escalate incident to higher priority or human intervention."""
        try:
            self.logger.warning(f"Escalating incident {incident.id}")
            
            incident.escalated = True
            incident.escalated_at = datetime.now()
            
            # Increase severity if possible
            if incident.severity != IncidentSeverity.CRITICAL:
                severities = list(IncidentSeverity)
                current_index = severities.index(incident.severity)
                if current_index > 0:
                    incident.severity = severities[current_index - 1]
            
            await self._trigger_callbacks('escalation_triggered', incident)
            self.metrics.increment('incidents_escalated')
            
        except Exception as e:
            self.logger.error(f"Error escalating incident {incident.id}: {e}")
    
    async def _cleanup_completed_incidents(self):
        """Clean up completed incidents and archive them."""
        completed_incidents = []
        
        for incident_id, incident in self.active_incidents.items():
            if incident.status in [IncidentStatus.CLOSED, IncidentStatus.RESOLVED]:
                # Check if incident has been completed for sufficient time
                if incident.resolved_at and (
                    datetime.now() - incident.resolved_at
                ).total_seconds() > 3600:  # 1 hour
                    completed_incidents.append(incident_id)
        
        # Archive completed incidents
        for incident_id in completed_incidents:
            incident = self.active_incidents.pop(incident_id)
            await self._archive_incident(incident)
    
    async def _archive_incident(self, incident: Incident):
        """Archive completed incident."""
        try:
            # This would save to persistent storage
            self.logger.info(f"Archiving incident {incident.id}")
            
            # Clean up any remaining tasks
            for task_dict in [self.analysis_tasks, self.response_tasks]:
                if incident.id in task_dict:
                    task = task_dict.pop(incident.id)
                    if not task.done():
                        task.cancel()
            
            await self._trigger_callbacks('incident_closed', incident)
            
        except Exception as e:
            self.logger.error(f"Error archiving incident {incident.id}: {e}")
    
    async def _collect_incident_metrics(self):
        """Collect metrics about incident response performance."""
        try:
            # Count incidents by status
            status_counts = {}
            severity_counts = {}
            
            for incident in self.active_incidents.values():
                status = incident.status.value
                severity = incident.severity.value
                
                status_counts[status] = status_counts.get(status, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Update metrics
            for status, count in status_counts.items():
                self.metrics.set_gauge(f'incidents_by_status_{status}', count)
            
            for severity, count in severity_counts.items():
                self.metrics.set_gauge(f'incidents_by_severity_{severity}', count)
            
            # Total active incidents
            self.metrics.set_gauge('active_incidents_total', len(self.active_incidents))
            
        except Exception as e:
            self.logger.error(f"Error collecting incident metrics: {e}")
    
    async def _trigger_callbacks(self, event_type: str, incident: Incident):
        """Trigger registered callbacks for incident events."""
        try:
            callbacks = self.incident_callbacks.get(event_type, [])
            
            for callback in callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(incident)
                    else:
                        callback(incident)
                except Exception as e:
                    self.logger.error(f"Error in callback for {event_type}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error triggering callbacks for {event_type}: {e}")
    
    def register_callback(self, event_type: str, callback: Callable):
        """Register callback for incident events."""
        if event_type in self.incident_callbacks:
            self.incident_callbacks[event_type].append(callback)
        else:
            raise ValueError(f"Unknown event type: {event_type}")
    
    async def manual_incident_response(self, incident_id: str, action: str, parameters: Dict[str, Any] = None):
        """Manually trigger incident response action."""
        if incident_id not in self.active_incidents:
            raise ValueError(f"Incident {incident_id} not found")
        
        incident = self.active_incidents[incident_id]
        
        if action == "analyze":
            if incident_id not in self.analysis_tasks:
                task = asyncio.create_task(self._analyze_incident(incident))
                self.analysis_tasks[incident_id] = task
        
        elif action == "respond":
            if incident_id not in self.response_tasks:
                task = asyncio.create_task(self._respond_to_incident(incident))
                self.response_tasks[incident_id] = task
        
        elif action == "escalate":
            await self._escalate_incident(incident)
        
        elif action == "close":
            incident.status = IncidentStatus.CLOSED
            incident.resolved_at = datetime.now()
            await self._trigger_callbacks('incident_updated', incident)
        
        else:
            raise ValueError(f"Unknown action: {action}")
    
    def get_active_incidents(self) -> List[Incident]:
        """Get list of all active incidents."""
        return list(self.active_incidents.values())
    
    def get_incident_statistics(self) -> Dict[str, Any]:
        """Get incident response statistics."""
        return {
            'active_incidents': len(self.active_incidents),
            'detection_tasks': len(self.detection_tasks),
            'analysis_tasks': len(self.analysis_tasks),
            'response_tasks': len(self.response_tasks),
            'metrics': self.metrics.get_all_metrics()
        }