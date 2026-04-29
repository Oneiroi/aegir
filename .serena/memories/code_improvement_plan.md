# Code Improvement Plan

## Overview
Fix 5 identified placeholder/incomplete implementations across the MCP Firewall codebase.

---

## Issue 1: `handleResourcesRead` - Placeholder Response
**File:** `internal/server/mcp_proxy.go`
**Problem:** Returns hardcoded text instead of actual resource data

### Changes Needed:
- Add method to fetch real resource content based on URI scheme
- For security:// URIs, return live scan results from sanitizer/compliance manager  
- For other valid URIs, attempt upstream fetch or return structured response
- Remove placeholder string

---

## Issue 2: `tokenizeCardData` - Static Tokenization  
**File:** `internal/sanitizer/compliance.go`
**Problem:** Returns static placeholders instead of preserving actual card digits

### Changes Needed:
- Modify function signature to accept original card number parameter
- Extract and preserve last 4 digits from actual card number
- Update all call sites in `detectPCI` to pass the matched card text
- Format output as `XXXX-XXXX-XXXX-{last4}`

---

## Issue 3: Least Connections Load Balancing
**File:** `internal/upstream/manager.go`
**Problem:** Falls back to round-robin with no real connection tracking

### Changes Needed:
- Add `ActiveConnections` field to `ServiceState` struct
- Track connections incrementing/decrementing in `forwardRequest`
- Implement proper comparison logic for least connections selection
- Update `selectLeastConnections` method

---

## Issue 4: Pagination Support
**Files:** `internal/server/mcp_proxy.go` (handlers)
**Problem:** Cursor parameter read but never used

### Changes Needed:
- Add pagination support to resources/tools/prompts list handlers
- Parse cursor and limit parameters properly
- Implement slice indexing based on cursor position
- Return next_cursor when more items exist

---

## Issue 5: Logger Status Tracking
**File:** `internal/logging/logger.go`
**Problem:** Hardcoded integrity status and last check time

### Changes Needed:
- Add `lastIntegrityCheck` field to Logger struct
- Add `integrityStatus` field to track actual health state
- Update `ValidateIntegrity()` to update these fields on each run
- Modify `GetStatus()` to return real tracked values instead of hardcoded ones

---

## Implementation Order:
1. Fix Issue 5 (Logger status) - Simple struct additions
2. Fix Issue 3 (Least connections) - Small addition to ServiceState
3. Fix Issue 2 (Tokenize card data) - Function signature change + call sites
4. Fix Issue 4 (Pagination) - Update list handlers
5. Fix Issue 1 (Resources read) - Most complex, depends on upstream logic