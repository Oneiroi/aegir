# Session Analyzer Integration

## Summary
Successfully integrated the ConversationalThreatAnalyzer into the MCP request pipeline to detect and block multi-turn attacks (jailbreaks, role escalation, context poisoning, etc.).

## Changes Made

### 1. internal/server/server.go
- Added import for `session` package
- Added `sessionAnalyzer *session.ConversationalThreatAnalyzer` field to MCPFirewall struct
- Initialize session analyzer in `New()` function using config.SessionAnalysis settings
- Pass analyzer to MCPProxy constructor with nil-safe handling
- Added three new API endpoints under `/api/security`:
  - `GET /security/sessions` - Returns session statistics
  - `GET /security/sessions/:id` - Returns specific session details
  - `DELETE /security/sessions/:id` - Removes a session

### 2. internal/server/mcp_proxy.go
- Added import for `session` package
- Added `sessionAnalyzer *session.ConversationalThreatAnalyzer` field to MCPProxy struct
- Updated `NewMCPProxy()` to accept analyzer parameter
- Modified `HandleMCPRequest()`:
  - Session analysis happens AFTER parsing request but BEFORE sanitization
  - Extracts session_id and user_id from context (with fallback to anonymous)
  - Calls `analyzer.AnalyzeMessage()` with params
  - Blocks requests with risk level "critical" or "high" (returns HTTP 403)
- Added helper functions:
  - `getSessionID(c)` - Extracts or generates session ID from context
  - `getUserID(c)` - Extracts user ID from context (already existed)

### 3. internal/session/analyzer.go
- Added `GetSessionContext(sessionID string) *SessionContext` method to retrieve specific session
- Added `DeleteSession(sessionID string)` method to remove session

## Request Flow
1. Parse incoming MCP request
2. **Session Analysis (NEW)** - Detect multi-turn attack patterns
   - Role escalation attempts
   - Jailbreak progression
   - Context poisoning
   - Template injection
   - Emotional manipulation
3. Return 403 Forbidden if threat level is critical or high
4. Continue with sanitization and compliance checks

## Configuration
Session analyzer is conditionally enabled via config.SessionAnalysis.Enabled setting with configurable thresholds:
- MaxSessionAge
- MaxHistorySize
- ThreatThreshold
- CleanupInterval
- JailbreakThreshold
- RoleEscalationLimit

## Backward Compatibility
- Analyzer is nil-safe - endpoints return 503 if not enabled
- Session analysis is optional and controlled via configuration
- No changes to existing security pipeline order (analysis happens before sanitization)
