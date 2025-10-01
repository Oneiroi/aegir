# Aegir

A comprehensive security gateway for Model Context Protocol (MCP) servers that implements enterprise-grade security controls, compliance frameworks, and threat protection.

## Features

### 🔐 Security Controls

- **Multi-layer Authentication**
  - JWT with RSA/ECDSA verification
  - OAuth 2.0/OIDC integration
  - API key authentication
  - Multi-factor authentication (MFA)

- **Transport Security**
  - TLS 1.3 enforcement
  - Certificate management
  - Perfect Forward Secrecy (PFS)
  - HSTS headers

- **Content Security**
  - Command injection prevention
  - XSS protection
  - SQL injection prevention
  - Homoglyph attack detection
  - Spreadsheet formula sanitization

### 🛡️ Threat Protection

- **Secret Detection & Redaction**
  - API keys, SSH keys, certificates
  - Database credentials
  - JWT tokens
  - Custom secret patterns

- **Rate Limiting**
  - Per-client rate limiting
  - Burst protection
  - Adaptive thresholds
  - DDoS mitigation

- **Data Encryption**
  - AES-256-GCM encryption
  - Automated key rotation
  - Hardware HSM support
  - Cloud KMS integration

### 📋 Compliance Frameworks

- **GDPR/CCPA**
  - PII detection and redaction
  - Right to erasure
  - Data portability
  - Consent tracking

- **HIPAA**
  - PHI detection and protection
  - Medical record number redaction
  - Healthcare-specific patterns
  - Audit trail compliance

- **PCI DSS**
  - Credit card number detection
  - CVV/CVC redaction
  - Payment data tokenization
  - Cardholder data protection

- **SOC 2 Type II**
  - Security controls
  - Availability monitoring
  - Confidentiality protection

### 📊 Security Monitoring

- **Comprehensive Logging**
  - HMAC integrity protection
  - Tamper-evident logs
  - Real-time threat detection
  - Compliance reporting

- **Security API**
  - Log integrity validation
  - Performance metrics
  - Connection monitoring
  - Incident response integration

## Quick Start

### Prerequisites

- Go 1.21 or later
- OpenSSL (for certificate generation)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/aegishjalmur/aegir.git
   cd aegir
   ```

2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

3. Edit `.env` with your configuration settings

4. Generate TLS certificates for development:
   ```bash
   make certs
   ```

5. Build and run:
   ```bash
   make build
   make run
   ```

### Development

Run in development mode with hot reload:
```bash
make dev
```

Run tests:
```bash
make test
```

### Configuration

The firewall is configured via environment variables. See `.env.example` for all available options.

Key configuration sections:

- **Server**: Port, TLS settings, timeouts
- **Authentication**: JWT, OAuth, API keys, MFA
- **Security**: Rate limiting, sanitization, encryption
- **Compliance**: GDPR, HIPAA, PCI DSS, SOC 2
- **Logging**: Format, integrity, audit trail

## API Endpoints

### Health Check
```bash
GET /health
```

### Authentication
```bash
POST /auth/login
POST /auth/refresh
POST /auth/logout
GET  /auth/oauth/login
GET  /auth/oauth/callback
```

### MCP Proxy
```bash
POST /mcp/resources
POST /mcp/tools
POST /mcp/prompts
WS   /mcp/ws
```

### Security API
```bash
GET /api/security/logging/status
GET /api/security/logging/validate
GET /api/security/metrics
```

## Default Credentials

For development, a default admin user is created:
- **Username**: `admin`
- **Password**: `admin123`
- **API Key**: Generated on startup (check logs)

**⚠️ Change these credentials in production!**

## Security Features

### Content Sanitization

The firewall automatically detects and neutralizes:

- Command injection attempts → `UNSAFE_COMMAND_REMOVED`
- Secret leakage → `UNSAFE_SECRETS_REMOVED`
- XSS vectors → `UNSAFE_SCRIPT_REMOVED`
- SQL injection → `UNSAFE_SQL_REMOVED`
- Homoglyph attacks → `UNSAFE_HOMOGLYPH_REMOVED`
- Spreadsheet formulas → `UNSAFE_SPREADSHEET_FORMULA`

### Compliance Data Protection

Automatically redacts sensitive data:

- **PII**: SSNs, emails, addresses → `PII_REDACTED`
- **PHI**: Medical records, diagnoses → `PHI_REDACTED`
- **PCI**: Credit cards, CVVs → `CARD_DATA_REDACTED`

### Log Integrity

All logs include HMAC signatures for tamper detection:
```
timestamp client_ip:port server_ip:port session_id event_type sha256(data) status_code hmac_signature
```

## Production Deployment

### Security Checklist

- [ ] Change default admin credentials
- [ ] Configure OAuth/OIDC provider
- [ ] Set up proper TLS certificates
- [ ] Configure HSM or cloud KMS
- [ ] Enable MFA for admin accounts
- [ ] Set up log monitoring and SIEM
- [ ] Configure backup and disaster recovery
- [ ] Review and tune rate limits
- [ ] Enable compliance frameworks as needed
- [ ] Test incident response procedures

### Environment Variables

Critical settings for production:

```bash
MCP_ENV=production
JWT_SECRET=your-256-bit-secret
LOG_HMAC_KEY=your-256-bit-hmac-key
TLS_ENABLED=true
RATE_LIMIT_ENABLED=true
MFA_REQUIRED=true
```

### Monitoring

Set up monitoring for:
- Authentication failures
- Rate limit violations
- Compliance data detections
- Log integrity failures
- Certificate expiration
- Key rotation status

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

BSL License - see [LICENSE](LICENSE) file for details.

## Support

For issues and questions:
- GitHub Issues: [https://github.com/oneiroi/aegir/issues](https://github.com/oneiroi/aegir/issues)
- Security Issues: security@oneiroi.co.uk

## Compliance Certifications

- SOC 2 Type II ready
- GDPR compliant
- HIPAA Business Associate ready
- PCI DSS Level 1 compatible
