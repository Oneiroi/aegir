// Package tasks provides async task tracking and quota management for MCP.
// ISC-171/172: Tracks per-identity async tasks with configurable concurrency caps,
// and cancels tasks on client disconnect.
package tasks

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TaskStatus represents the current state of a task.
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCancelled TaskStatus = "cancelled"
	TaskStatusFinished  TaskStatus = "finished"
)

// TaskInfo holds metadata about a running task.
type TaskInfo struct {
	ID           string
	UserID       string
	TenantID     string
	Status       TaskStatus
	CreatedAt    time.Time
	StartedAt    time.Time
	CancelCtx    context.Context
	CancelFunc   context.CancelFunc
	parentCtx    context.Context
	parentCancel context.CancelFunc
}

// Registry manages async tasks with per-identity quotas.
type Registry struct {
	mu             sync.RWMutex
	tasks          map[string]*TaskInfo // taskID → task info
	userTasks      map[string][]string  // userID → list of task IDs
	tenantTasks    map[string][]string  // tenantID → list of task IDs
	maxConcurrency int                  // max tasks per identity
	maxTotal       int                  // total max tasks
	taskTimeout    time.Duration        // default task timeout
}

// Config holds configuration for the task registry.
type Config struct {
	MaxConcurrency int           // max concurrent tasks per identity (default: 5)
	MaxTotal       int           // max total tasks across all identities (default: 100)
	TaskTimeout    time.Duration // default task timeout (default: 5m)
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxConcurrency: 5,
		MaxTotal:       100,
		TaskTimeout:    5 * time.Minute,
	}
}

// NewRegistry creates a new task registry with the given configuration.
func NewRegistry(cfg Config) *Registry {
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 5
	}
	if cfg.MaxTotal <= 0 {
		cfg.MaxTotal = 100
	}
	if cfg.TaskTimeout <= 0 {
		cfg.TaskTimeout = 5 * time.Minute
	}

	return &Registry{
		tasks:          make(map[string]*TaskInfo),
		userTasks:      make(map[string][]string),
		tenantTasks:    make(map[string][]string),
		maxConcurrency: cfg.MaxConcurrency,
		maxTotal:       cfg.MaxTotal,
		taskTimeout:    cfg.TaskTimeout,
	}
}

// StartTask registers a new task and returns its context for cancellation.
// Returns (nil, false) if the quota is exceeded.
func (r *Registry) StartTask(taskID, userID, tenantID string) (context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check total task limit
	if len(r.tasks) >= r.maxTotal {
		return nil, false
	}

	// Check per-user concurrency limit
	userTaskCount := len(r.userTasks[userID])
	if userTaskCount >= r.maxConcurrency {
		return nil, false
	}

	// Create context with timeout
	cancelCtx, cancelFunc := context.WithTimeout(context.Background(), r.taskTimeout)

	// Register task
	taskInfo := &TaskInfo{
		ID:         taskID,
		UserID:     userID,
		TenantID:   tenantID,
		Status:     TaskStatusPending,
		CreatedAt:  time.Now(),
		CancelCtx:  cancelCtx,
		CancelFunc: cancelFunc,
	}
	r.tasks[taskID] = taskInfo

	// Track by user
	r.userTasks[userID] = append(r.userTasks[userID], taskID)

	// Track by tenant
	r.tenantTasks[tenantID] = append(r.tenantTasks[tenantID], taskID)

	return cancelCtx, true
}

// StartTaskWithUserContext creates a task with a user-supplied context.
// Returns (nil, false) if the quota is exceeded.
func (r *Registry) StartTaskWithUserContext(taskID, userID, tenantID string, userCtx context.Context) (context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check total task limit
	if len(r.tasks) >= r.maxTotal {
		return nil, false
	}

	// Check per-user concurrency limit
	userTaskCount := len(r.userTasks[userID])
	if userTaskCount >= r.maxConcurrency {
		return nil, false
	}

	// Create parent context with timeout
	parentCtx, cancelParent := context.WithTimeout(context.Background(), r.taskTimeout)

	// Create child context that is cancelled if parent is cancelled or userCtx is done
	cancelCtx, childCancel := context.WithCancel(parentCtx)

	go func() {
		select {
		case <-userCtx.Done():
			childCancel()
		case <-parentCtx.Done():
		}
	}()

	// Register task
	taskInfo := &TaskInfo{
		ID:           taskID,
		UserID:       userID,
		TenantID:     tenantID,
		Status:       TaskStatusPending,
		CreatedAt:    time.Now(),
		CancelCtx:    cancelCtx,
		CancelFunc:   childCancel,
		parentCtx:    parentCtx,
		parentCancel: cancelParent,
	}
	r.tasks[taskID] = taskInfo

	// Track by user
	r.userTasks[userID] = append(r.userTasks[userID], taskID)

	// Track by tenant
	r.tenantTasks[tenantID] = append(r.tenantTasks[tenantID], taskID)

	return cancelCtx, true
}

// MarkRunning updates the task status to running.
func (r *Registry) MarkRunning(taskID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, exists := r.tasks[taskID]
	if !exists {
		return false
	}
	task.Status = TaskStatusRunning
	task.StartedAt = time.Now()
	return true
}

// MarkFinished marks a task as finished and removes it from tracking.
func (r *Registry) MarkFinished(taskID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, exists := r.tasks[taskID]
	if !exists {
		return false
	}
	task.Status = TaskStatusFinished
	r.removeTaskLocked(taskID, task.UserID, task.TenantID)
	return true
}

// CancelTask cancels a task and marks it as cancelled.
func (r *Registry) CancelTask(taskID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	task, exists := r.tasks[taskID]
	if !exists {
		return false
	}
	task.Status = TaskStatusCancelled
	task.CancelFunc()
	r.removeTaskLocked(taskID, task.UserID, task.TenantID)
	return true
}

// CancelTasksForUser cancels all tasks for a given user.
func (r *Registry) CancelTasksForUser(userID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Snapshot the slice: removeTaskLocked mutates r.userTasks[userID] in place,
	// so ranging over the live slice would skip elements.
	taskIDs := append([]string(nil), r.userTasks[userID]...)
	count := 0
	for _, taskID := range taskIDs {
		if task, exists := r.tasks[taskID]; exists {
			task.Status = TaskStatusCancelled
			task.CancelFunc()
			r.removeTaskLocked(taskID, userID, task.TenantID)
			count++
		}
	}
	return count
}

// CancelTasksForTenant cancels all tasks for a given tenant.
func (r *Registry) CancelTasksForTenant(tenantID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Snapshot the slice: removeTaskLocked mutates r.tenantTasks[tenantID] in place,
	// so ranging over the live slice would skip elements.
	taskIDs := append([]string(nil), r.tenantTasks[tenantID]...)
	count := 0
	for _, taskID := range taskIDs {
		if task, exists := r.tasks[taskID]; exists {
			task.Status = TaskStatusCancelled
			task.CancelFunc()
			r.removeTaskLocked(taskID, task.UserID, tenantID)
			count++
		}
	}
	return count
}

// GetTask returns the tracked task for the given ID, if any. Used by the
// resumable-state lookup path (ISC-175/176) after the caller's signed token
// has already been verified against the requesting identity — this method
// itself does not check ownership, so callers must not expose it directly to
// an unverified caller.
func (r *Registry) GetTask(taskID string) (*TaskInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	task, ok := r.tasks[taskID]
	return task, ok
}

// GetTaskCount returns the number of tasks for a user.
func (r *Registry) GetTaskCount(userID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.userTasks[userID])
}

// GetTaskCountByTenant returns the number of tasks for a tenant.
func (r *Registry) GetTaskCountByTenant(tenantID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tenantTasks[tenantID])
}

// GetTotalTaskCount returns the total number of tracked tasks.
func (r *Registry) GetTotalTaskCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tasks)
}

// GetTasksForUser returns all tasks for a user.
func (r *Registry) GetTasksForUser(userID string) []*TaskInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	taskIDs := r.userTasks[userID]
	result := make([]*TaskInfo, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		if task, exists := r.tasks[taskID]; exists {
			result = append(result, task)
		}
	}
	return result
}

// GetTasksForTenant returns all tasks for a tenant.
func (r *Registry) GetTasksForTenant(tenantID string) []*TaskInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	taskIDs := r.tenantTasks[tenantID]
	result := make([]*TaskInfo, 0, len(taskIDs))
	for _, taskID := range taskIDs {
		if task, exists := r.tasks[taskID]; exists {
			result = append(result, task)
		}
	}
	return result
}

// removeTaskLocked removes a task from tracking (must hold lock).
func (r *Registry) removeTaskLocked(taskID, userID, tenantID string) {
	delete(r.tasks, taskID)

	// Remove from user tracking
	if tasks, exists := r.userTasks[userID]; exists {
		for i, id := range tasks {
			if id == taskID {
				r.userTasks[userID] = append(tasks[:i], tasks[i+1:]...)
				break
			}
		}
	}

	// Remove from tenant tracking
	if tasks, exists := r.tenantTasks[tenantID]; exists {
		for i, id := range tasks {
			if id == taskID {
				r.tenantTasks[tenantID] = append(tasks[:i], tasks[i+1:]...)
				break
			}
		}
	}
}

// CleanupExpired removes tasks that have exceeded their timeout.
func (r *Registry) CleanupExpired() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	count := 0
	for taskID, task := range r.tasks {
		if now.Sub(task.CreatedAt) > r.taskTimeout && task.Status == TaskStatusPending {
			task.Status = TaskStatusCancelled
			task.CancelFunc()
			r.removeTaskLocked(taskID, task.UserID, task.TenantID)
			count++
		}
	}
	return count
}

// TaskNotFoundError is returned when a task is not found.
type TaskNotFoundError struct {
	TaskID string
}

func (e *TaskNotFoundError) Error() string {
	return fmt.Sprintf("task not found: %s", e.TaskID)
}

// TaskQuotaExceededError is returned when the task quota is exceeded.
type TaskQuotaExceededError struct {
	UserID         string
	MaxConcurrency int
	CurrentCount   int
}

func (e *TaskQuotaExceededError) Error() string {
	return fmt.Sprintf("task quota exceeded for user %s: %d/%d", e.UserID, e.CurrentCount, e.MaxConcurrency)
}

// TotalQuotaExceededError is returned when the total task quota is exceeded.
type TotalQuotaExceededError struct {
	MaxTotal     int
	CurrentCount int
}

func (e *TotalQuotaExceededError) Error() string {
	return fmt.Sprintf("total task quota exceeded: %d/%d", e.CurrentCount, e.MaxTotal)
}
