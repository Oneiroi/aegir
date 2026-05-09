# Todo Plan

## Status: COMPLETE

All 5 issues resolved. Build clean. TestGracefulShutdown pre-existing failure (unrelated).

### Issue 2 (Tokenize Card Data) - COMPLETED ✓
- Syntax error was already fixed prior to this session

### Issue 3 (Least Connections) - COMPLETED ✓
- Added connection tracking with increment/decrement in forwardRequest

### Issue 4 (Pagination) - COMPLETED ✓
- handleResourcesList, handleToolsList, handlePromptsList all implement cursor-based pagination
- Cursor = strconv.Atoi string offset; page size 50; nextCursor set when more items exist

### Issue 1 (handleResourcesRead) - COMPLETED ✓
- security://scan/content → returns scanner capabilities JSON
- security://policy/status → returns policy/component status JSON
- Other URIs → returns MCPError -32000 upstream unavailable

### Issue 5 (Logger status) - COMPLETED ✓
- GetStatus() already using real integrityStatus/lastIntegrityCheck fields
- ValidateIntegrity() already updating those fields