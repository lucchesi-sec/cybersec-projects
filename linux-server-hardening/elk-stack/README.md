# ELK Stack Integration for Centralized Logging

This directory contains configuration files and instructions for setting up centralized logging using the ELK (Elasticsearch, Logstash, Kibana) Stack.

## Prerequisites

- Docker and Docker Compose installed
- At least 4GB RAM available for the ELK stack
- Ports 9200, 5601, and 5044 available

## Directory Structure

```
elk-stack/
├── docker-compose.yml    # Docker Compose configuration for ELK stack
├── logstash/
│   ├── config/          # Logstash configuration files
│   └── pipelines/       # Logstash pipeline configurations
├── elasticsearch/
│   └── config/          # Elasticsearch configuration
└── kibana/
    └── config/          # Kibana configuration
```

## Quick Start

1. Clone this repository
2. Navigate to the elk-stack directory
3. Run `docker-compose up -d`
4. Access Kibana at http://localhost:5601

## Configuration Details

### Elasticsearch
- Runs on port 9200
- Default credentials: elastic/changeme
- Configured with basic security settings

### Logstash
- Runs on port 5044 (Beats input)
- Configured to collect logs from:
  - System logs (/var/log/syslog)
  - SSH logs (/var/log/auth.log)
  - Audit logs (/var/log/audit/audit.log)
  - Application logs

### Kibana
- Runs on port 5601
- Pre-configured dashboards for:
  - System security overview
  - SSH access monitoring
  - Failed login attempts
  - Audit log analysis

## Security Considerations

1. Change default passwords
2. Enable SSL/TLS for all components
3. Configure firewall rules
4. Set up proper authentication
5. Regular backup of Elasticsearch data

## Monitoring and Maintenance

- Regular log rotation
- Index lifecycle management
- Performance monitoring
- Backup procedures

## Integration with Existing Security Tools

The ELK stack is configured to work with:
- fail2ban
- auditd
- SSH logging
- System logs

## Troubleshooting

Common issues and solutions are documented in the troubleshooting guide.
