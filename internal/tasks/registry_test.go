package tasks

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestAsyncTaskQuotaEnforced verifies that ISC-171 enforces per-identity quotas.
func TestAsyncTaskQuotaEnforced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrency = 2
	registry := NewRegistry(cfg)

	userID := "test-user"
	tenantID := "test-tenant"

	// Start first task
	ctx1, ok := registry.StartTask("task-1", userID, tenantID)
	if !ok {
		t.Errorf("Expected first task to be allowed")
	}
	if ctx1 == nil {
		t.Errorf("Expected context to be non-nil")
	}

	// Start second task
	ctx2, ok := registry.StartTask("task-2", userID, tenantID)
	if !ok {
		t.Errorf("Expected second task to be allowed")
	}
	if ctx2 == nil {
		t.Errorf("Expected context to be non-nil")
	}

	// Third task should be rejected due to quota
	ctx3, ok := registry.StartTask("task-3", userID, tenantID)
	if ok {
		t.Errorf("Expected third task to be rejected due to quota")
	}
	if ctx3 != nil {
		t.Errorf("Expected context to be nil when quota exceeded")
	}
}

// TestTaskCancelledOnClientDisconnect verifies that ISC-172 cancels tasks
// when the client disconnects.
func TestTaskCancelledOnClientDisconnect(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	userID := "test-user"
	tenantID := "test-tenant"

	// Create a context that will be cancelled (simulating client disconnect)
	clientCtx, clientCancel := context.WithCancel(context.Background())

	// Start task with user context
	ctx, ok := registry.StartTaskWithUserContext("task-1", userID, tenantID, clientCtx)
	if !ok {
		t.Errorf("Expected task to be started")
	}

	// Cancel client context (simulating disconnect)
	clientCancel()

	// Wait a moment for the goroutine to propagate cancellation
	time.Sleep(10 * time.Millisecond)

	// Context should be cancelled
	select {
	case <-ctx.Done():
		// Expected - context was cancelled
	default:
		t.Errorf("Expected task context to be cancelled after client disconnect")
	}
}

// TestTaskCountPerUser verifies that task counts are tracked per user.
func TestTaskCountPerUser(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	// User 1 starts 3 tasks
	for i := 1; i <= 3; i++ {
		registry.StartTask(fmt.Sprintf("user1-task%d", i), "user1", "tenant1")
	}

	// User 2 starts 2 tasks
	for i := 1; i <= 2; i++ {
		registry.StartTask(fmt.Sprintf("user2-task%d", i), "user2", "tenant1")
	}

	// Verify counts
	if count := registry.GetTaskCount("user1"); count != 3 {
		t.Errorf("Expected user1 to have 3 tasks, got %d", count)
	}
	if count := registry.GetTaskCount("user2"); count != 2 {
		t.Errorf("Expected user2 to have 2 tasks, got %d", count)
	}
	if total := registry.GetTotalTaskCount(); total != 5 {
		t.Errorf("Expected total of 5 tasks, got %d", total)
	}
}

// TestTotalQuotaEnforced verifies that total task quota is enforced.
func TestTotalQuotaEnforced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxTotal = 2
	registry := NewRegistry(cfg)

	// Start two tasks
	registry.StartTask("task-1", "user1", "tenant1")
	registry.StartTask("task-2", "user2", "tenant1")

	// Third task should be rejected
	_, ok := registry.StartTask("task-3", "user3", "tenant1")
	if ok {
		t.Errorf("Expected third task to be rejected due to total quota")
	}
}

// TestMarkFinished removes task from tracking.
func TestMarkFinished(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	registry.StartTask("task-1", "user1", "tenant1")
	if registry.GetTotalTaskCount() != 1 {
		t.Errorf("Expected 1 task before finish")
	}

	registry.MarkFinished("task-1")
	if registry.GetTotalTaskCount() != 0 {
		t.Errorf("Expected 0 tasks after finish")
	}
}

// TestMarkCancelled cancels task and removes from tracking.
func TestMarkCancelled(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	ctx, ok := registry.StartTask("task-1", "user1", "tenant1")
	if !ok {
		t.Errorf("Expected task to be started")
	}

	registry.CancelTask("task-1")
	if registry.GetTotalTaskCount() != 0 {
		t.Errorf("Expected 0 tasks after cancel")
	}

	// Context should be cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Errorf("Expected context to be cancelled")
	}
}

// TestCancelTasksForUser cancels all tasks for a user.
func TestCancelTasksForUser(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	// Start 3 tasks for user1
	for i := 1; i <= 3; i++ {
		registry.StartTask(fmt.Sprintf("task-%d", i), "user1", "tenant1")
	}

	// Start 2 tasks for user2
	for i := 1; i <= 2; i++ {
		registry.StartTask(fmt.Sprintf("task-%d", i+3), "user2", "tenant1")
	}

	// Cancel all tasks for user1
	cancelled := registry.CancelTasksForUser("user1")
	if cancelled != 3 {
		t.Errorf("Expected 3 tasks cancelled for user1, got %d", cancelled)
	}

	// Verify user1 has 0 tasks, user2 still has 2
	if registry.GetTaskCount("user1") != 0 {
		t.Errorf("Expected user1 to have 0 tasks after cancel")
	}
	if registry.GetTaskCount("user2") != 2 {
		t.Errorf("Expected user2 to have 2 tasks after user1 cancel")
	}
}

// TestGetTasksForUser returns all tasks for a user.
func TestGetTasksForUser(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	registry.StartTask("task-1", "user1", "tenant1")
	registry.StartTask("task-2", "user1", "tenant1")
	registry.StartTask("task-3", "user2", "tenant1")

	tasks := registry.GetTasksForUser("user1")
	if len(tasks) != 2 {
		t.Errorf("Expected 2 tasks for user1, got %d", len(tasks))
	}
}

// TestCancelTasksForTenant cancels all tasks for a tenant.
func TestCancelTasksForTenant(t *testing.T) {
	registry := NewRegistry(DefaultConfig())

	// User1 has 2 tasks in tenant1
	registry.StartTask("task-1", "user1", "tenant1")
	registry.StartTask("task-2", "user1", "tenant1")

	// User2 has 1 task in tenant1
	registry.StartTask("task-3", "user2", "tenant1")

	// User3 has 2 tasks in tenant2
	registry.StartTask("task-4", "user3", "tenant2")
	registry.StartTask("task-5", "user3", "tenant2")

	// Cancel all tasks for tenant1
	cancelled := registry.CancelTasksForTenant("tenant1")
	if cancelled != 3 {
		t.Errorf("Expected 3 tasks cancelled for tenant1, got %d", cancelled)
	}

	// Verify tenant1 has 0 tasks, tenant2 still has 2
	if registry.GetTaskCountByTenant("tenant1") != 0 {
		t.Errorf("Expected tenant1 to have 0 tasks after cancel")
	}
	if registry.GetTaskCountByTenant("tenant2") != 2 {
		t.Errorf("Expected tenant2 to have 2 tasks after tenant1 cancel")
	}
}
