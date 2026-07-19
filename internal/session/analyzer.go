package session

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aegishjalmur/aegir/internal/logging"
)

// ConversationalThreatAnalyzer detects multi-turn attack patterns
type ConversationalThreatAnalyzer struct {
	sessions       map[string]*SessionContext
	userSessions   map[string]map[string]*SessionContext // user_id -> session_id -> session
	mutex          sync.RWMutex
	logger         *logging.Logger
	config         AnalyzerConfig
	attackPatterns map[string]*AttackPattern
	seqPatterns    []SequencePattern
	done           chan struct{}
}

// SlidingWindowStats tracks repetition statistics over sliding windows
type SlidingWindowStats struct {
	WindowStart       time.Time `json:"window_start"`
	MessageCount      int       `json:"message_count"`
	QueryPatterns     []string  `json:"query_patterns"`
	RepetitionCount   int       `json:"repetition_count"`
	UniformityScore   float64   `json:"uniformity_score"`
	MaxRepetition     int       `json:"max_repetition"`
	RepetitionHistory []int     `json:"repetition_history"`
}

// ModelExtractionReport tracks model extraction detection results
type ModelExtractionReport struct {
	Detected        bool     `json:"detected"`
	UniformityScore float64  `json:"uniformity_score"`
	RepetitionCount int      `json:"repetition_count"`
	MaxRepetition   int      `json:"max_repetition"`
	UniformQueries  []string `json:"uniform_queries"`
	DetectionMethod string   `json:"detection_method"`
	ConfidenceLevel string   `json:"confidence_level"`
}

// SessionContext tracks conversation state and threat indicators
type SessionContext struct {
	SessionID      string              `json:"session_id"`
	UserID         string              `json:"user_id"`
	StartTime      time.Time           `json:"start_time"`
	LastActivity   time.Time           `json:"last_activity"`
	MessageCount   int                 `json:"message_count"`
	ThreatScore    float64             `json:"threat_score"`
	RoleEscalation int                 `json:"role_escalation_attempts"`
	JailbreakScore float64             `json:"jailbreak_score"`
	History        []MessageContext    `json:"history"`
	Flags          map[string]int      `json:"flags"`
	Risk           string              `json:"risk_level"`
	SlidingWindow  *SlidingWindowStats `json:"sliding_window"`

	// ISC-16: rolling EWMA anomaly score across messages
	AnomalyEWMA float64 `json:"anomaly_ewma"`

	// ISC-112: ordered tool-call events for sequence detection
	ToolCalls []ToolCallEvent `json:"tool_calls"`
}

// MessageContext represents a single message in conversation
type MessageContext struct {
	Timestamp   time.Time `json:"timestamp"`
	Content     string    `json:"content"`
	ThreatScore float64   `json:"threat_score"`
	Detections  []string  `json:"detections"`
	Role        string    `json:"role,omitempty"`
	Intent      string    `json:"intent,omitempty"`
}

// AttackPattern defines multi-turn attack signatures
type AttackPattern struct {
	Name        string        `json:"name"`
	Stages      []string      `json:"stages"`
	MinMessages int           `json:"min_messages"`
	MaxTimespan time.Duration `json:"max_timespan"`
	ThreatLevel string        `json:"threat_level"`
	Indicators  []string      `json:"indicators"`
}

// ToolCallEvent records a single tool-call name with its timestamp (ISC-112)
type ToolCallEvent struct {
	Name      string    `json:"name"`
	Timestamp time.Time `json:"timestamp"`
}

// SequencePattern defines a high-risk ordered tool-call sequence (ISC-112)
// Steps may be exact names or prefix-glob patterns ending in "*" (e.g. "send_*")
type SequencePattern struct {
	Steps  []string      `json:"steps"`
	Window time.Duration `json:"window"`
}

// ContextProfile holds per-context threshold overrides (ISC-20, ISC-21).
// When an ActiveProfile is set on AnalyzerConfig, its non-zero fields replace
// the top-level threshold values after defaults are applied.
// Example profiles: "finance" (stricter), "assistant" (standard).
type ContextProfile struct {
	// ThreatThreshold overrides AnalyzerConfig.ThreatThreshold when > 0.
	ThreatThreshold float64 `json:"threat_threshold" mapstructure:"threat_threshold"`
	// AnomalyBlockThreshold overrides AnalyzerConfig.AnomalyBlockThreshold when > 0.
	AnomalyBlockThreshold float64 `json:"anomaly_block_threshold" mapstructure:"anomaly_block_threshold"`
	// JailbreakThreshold overrides AnalyzerConfig.JailbreakThreshold when > 0.
	JailbreakThreshold float64 `json:"jailbreak_threshold" mapstructure:"jailbreak_threshold"`
	// EntropyThreshold overrides AnalyzerConfig.EntropyThreshold when > 0.
	// Low-entropy content (short, repetitive) may warrant reduced sensitivity. (ISC-21)
	EntropyThreshold float64 `json:"entropy_threshold" mapstructure:"entropy_threshold"`
}

// AnalyzerConfig configures the conversational threat analyzer
type AnalyzerConfig struct {
	MaxSessionAge       time.Duration `json:"max_session_age"`
	MaxHistorySize      int           `json:"max_history_size"`
	ThreatThreshold     float64       `json:"threat_threshold"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
	JailbreakThreshold  float64       `json:"jailbreak_threshold"`
	RoleEscalationLimit int           `json:"role_escalation_limit"`
	SlidingWindowSize   time.Duration `json:"sliding_window_size"`
	RepetitionThreshold int           `json:"repetition_threshold"`
	UniformityThreshold float64       `json:"uniformity_threshold"`

	// ISC-16: EWMA smoothing factor α ∈ (0,1] and block threshold
	AnomalyEWMAAlpha      float64 `json:"anomaly_ewma_alpha"`
	AnomalyBlockThreshold float64 `json:"anomaly_block_threshold"`

	// ISC-16: EWMA decay half-life. The EWMA is decayed by elapsed time since
	// the last message so a session that stops receiving adversarial traffic
	// can recover instead of remaining latched. Zero or negative disables decay.
	AnomalyEWMADecayHalfLife time.Duration `json:"anomaly_ewma_decay_half_life"`

	// ISC-112: sliding window for sequence detection
	SequenceWindowSize time.Duration `json:"sequence_window_size"`

	// ISC-21: entropy threshold gates detection sensitivity for low-information content.
	// Content with Shannon entropy below this value may indicate low-signal messages.
	// Default 0.5. Configurable per MCP server upstream.
	EntropyThreshold float64 `json:"entropy_threshold" mapstructure:"entropy_threshold"`

	// ISC-20: named context profiles (e.g. "finance", "assistant").
	// Populated from aegir.yaml anomaly_detection.profiles map.
	Profiles map[string]ContextProfile `json:"profiles" mapstructure:"profiles"`

	// ISC-20: when non-empty, overrides top-level thresholds with values from Profiles[ActiveProfile].
	ActiveProfile string `json:"active_profile" mapstructure:"active_profile"`
}

// ThreatAssessment contains the analysis result
type ThreatAssessment struct {
	SessionID          string         `json:"session_id"`
	CurrentThreatScore float64        `json:"current_threat_score"`
	JailbreakRisk      float64        `json:"jailbreak_risk"`
	ConversationRisk   string         `json:"conversation_risk"`
	AttackPatterns     []string       `json:"detected_patterns"`
	RecommendedAction  string         `json:"recommended_action"`
	BlockConversation  bool           `json:"block_conversation"`
	Reasoning          []string       `json:"reasoning"`
	Indicators         map[string]int `json:"indicators"`
}

// ThreatAnalyzer is the interface for session-level threat analysis.
type ThreatAnalyzer interface {
	AnalyzeMessage(sessionID, userID, content string) *ThreatAssessment
}

// defaultHighRiskSequences returns the built-in high-risk tool-call sequence patterns
func defaultHighRiskSequences() []SequencePattern {
	return []SequencePattern{
		{Steps: []string{"list_credentials", "send_*"}, Window: 10 * time.Minute},
		{Steps: []string{"read_file", "upload_*"}, Window: 10 * time.Minute},
	}
}

// NewConversationalThreatAnalyzer creates a new analyzer
func NewConversationalThreatAnalyzer(config AnalyzerConfig, logger *logging.Logger) *ConversationalThreatAnalyzer {
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	if config.MaxSessionAge <= 0 {
		config.MaxSessionAge = 30 * time.Minute
	}
	if config.MaxHistorySize <= 0 {
		config.MaxHistorySize = 50
	}
	if config.ThreatThreshold <= 0 {
		config.ThreatThreshold = 0.5
	}
	if config.JailbreakThreshold <= 0 {
		config.JailbreakThreshold = 0.6
	}
	if config.RoleEscalationLimit <= 0 {
		config.RoleEscalationLimit = 3
	}
	if config.SlidingWindowSize <= 0 {
		config.SlidingWindowSize = 5 * time.Minute
	}
	if config.RepetitionThreshold <= 0 {
		config.RepetitionThreshold = 5
	}
	if config.UniformityThreshold <= 0 {
		config.UniformityThreshold = 0.8
	}
	// ISC-16 defaults
	if config.AnomalyEWMAAlpha <= 0 {
		config.AnomalyEWMAAlpha = 0.4 // moderate responsiveness
	}
	if config.AnomalyBlockThreshold <= 0 {
		config.AnomalyBlockThreshold = 0.70
	}
	if config.AnomalyEWMADecayHalfLife <= 0 {
		config.AnomalyEWMADecayHalfLife = 5 * time.Minute
	}
	// ISC-112 defaults
	if config.SequenceWindowSize <= 0 {
		config.SequenceWindowSize = 10 * time.Minute
	}
	// ISC-21: entropy threshold default
	if config.EntropyThreshold <= 0 {
		config.EntropyThreshold = 0.5
	}
	// ISC-20: apply active profile overrides after all defaults are set.
	// Only non-zero profile fields replace the top-level values so that partial
	// profiles (e.g. only ThreatThreshold set) leave other thresholds unchanged.
	if config.ActiveProfile != "" {
		if profile, ok := config.Profiles[config.ActiveProfile]; ok {
			if profile.ThreatThreshold > 0 {
				config.ThreatThreshold = profile.ThreatThreshold
			}
			if profile.AnomalyBlockThreshold > 0 {
				config.AnomalyBlockThreshold = profile.AnomalyBlockThreshold
			}
			if profile.JailbreakThreshold > 0 {
				config.JailbreakThreshold = profile.JailbreakThreshold
			}
			if profile.EntropyThreshold > 0 {
				config.EntropyThreshold = profile.EntropyThreshold
			}
		}
	}

	analyzer := &ConversationalThreatAnalyzer{
		sessions:       make(map[string]*SessionContext),
		userSessions:   make(map[string]map[string]*SessionContext),
		logger:         logger,
		config:         config,
		attackPatterns: make(map[string]*AttackPattern),
		seqPatterns:    defaultHighRiskSequences(),
		done:           make(chan struct{}),
	}

	// Initialize attack patterns
	analyzer.initializeAttackPatterns()

	// Start cleanup routine
	go analyzer.cleanupRoutine()

	return analyzer
}

// AnalyzeMessage processes a message and updates session context
func (cta *ConversationalThreatAnalyzer) AnalyzeMessage(sessionID, userID, content string) *ThreatAssessment {
	cta.mutex.Lock()
	defer cta.mutex.Unlock()

	// Get or create session
	session := cta.getOrCreateSession(sessionID, userID)

	// Analyze current message
	msgCtx := cta.analyzeMessageContent(content)

	// Update session context
	now := time.Now()
	// ISC-16: decay the EWMA based on elapsed time since the last message so a
	// session that stops receiving adversarial traffic can recover instead of
	// remaining permanently latched.
	if elapsed := now.Sub(session.LastActivity); elapsed > 0 {
		halfLife := cta.config.AnomalyEWMADecayHalfLife
		if halfLife > 0 {
			decay := math.Exp(-float64(elapsed) / float64(halfLife) * math.Ln2)
			session.AnomalyEWMA *= decay
		}
	}
	session.LastActivity = now
	session.MessageCount++
	session.History = append(session.History, msgCtx)

	// Maintain history size limit
	if len(session.History) > cta.config.MaxHistorySize {
		session.History = session.History[1:]
	}

	// ISC-112: extract tool-call name from content and record
	if toolName := extractToolCallName(content); toolName != "" {
		session.ToolCalls = append(session.ToolCalls, ToolCallEvent{
			Name:      toolName,
			Timestamp: msgCtx.Timestamp,
		})
	}

	// Perform conversational analysis
	assessment := cta.performConversationalAnalysis(session, msgCtx)

	// ISC-16: update rolling EWMA with the current threat score, then check threshold
	alpha := cta.config.AnomalyEWMAAlpha
	session.AnomalyEWMA = alpha*assessment.CurrentThreatScore + (1-alpha)*session.AnomalyEWMA
	if session.AnomalyEWMA >= cta.config.AnomalyBlockThreshold {
		assessment.ConversationRisk = "critical"
		assessment.BlockConversation = true
		assessment.RecommendedAction = "BLOCK_SESSION"
		assessment.Reasoning = append(assessment.Reasoning,
			fmt.Sprintf("Session anomaly EWMA %.2f exceeds block threshold %.2f",
				session.AnomalyEWMA, cta.config.AnomalyBlockThreshold))
	}

	// Update session threat score
	session.ThreatScore = assessment.CurrentThreatScore
	session.JailbreakScore = assessment.JailbreakRisk
	session.Risk = assessment.ConversationRisk

	// Log threat assessment
	if assessment.CurrentThreatScore > cta.config.ThreatThreshold {
		cta.logger.Info("SECURITY: Conversational threat detected",
			"session_id", sessionID,
			"user_id", userID,
			"threat_score", assessment.CurrentThreatScore,
			"jailbreak_risk", assessment.JailbreakRisk,
			"conversation_risk", assessment.ConversationRisk,
			"attack_patterns", assessment.AttackPatterns,
			"message_count", session.MessageCount,
			"anomaly_ewma", session.AnomalyEWMA,
		)
	}

	return assessment
}

// performConversationalAnalysis analyzes the conversation for threats
func (cta *ConversationalThreatAnalyzer) performConversationalAnalysis(session *SessionContext, currentMsg MessageContext) *ThreatAssessment {
	assessment := &ThreatAssessment{
		SessionID:          session.SessionID,
		CurrentThreatScore: 0.0,
		JailbreakRisk:      0.0,
		ConversationRisk:   "low",
		AttackPatterns:     []string{},
		Indicators:         make(map[string]int),
		Reasoning:          []string{},
	}

	// Analyze role escalation patterns
	cta.analyzeRoleEscalation(session, assessment)

	// Analyze jailbreak progression
	cta.analyzeJailbreakProgression(session, assessment)

	// Analyze context poisoning
	cta.analyzeContextPoisoning(session, assessment)

	// Analyze incremental template injection
	cta.analyzeTemplateInjection(session, assessment)

	// Analyze emotional manipulation
	cta.analyzeEmotionalManipulation(session, assessment)

	// Detect model extraction via sliding window repetition
	cta.detectModelExtraction(session, assessment)

	// ISC-112: detect high-risk tool-call sequences
	cta.detectSequenceAnomalies(session, assessment)

	// Calculate overall threat score
	assessment.CurrentThreatScore = cta.calculateOverallThreat(session, assessment)

	// Determine recommended action (may be upgraded by EWMA check in AnalyzeMessage)
	cta.determineRecommendedAction(assessment)

	return assessment
}

// detectSequenceAnomalies checks the session's tool-call history for high-risk sequences (ISC-112)
func (cta *ConversationalThreatAnalyzer) detectSequenceAnomalies(session *SessionContext, assessment *ThreatAssessment) {
	if len(session.ToolCalls) < 2 {
		return
	}

	now := time.Now()
	windowSize := cta.config.SequenceWindowSize

	// Prune events outside the window
	recentCalls := make([]ToolCallEvent, 0, len(session.ToolCalls))
	for _, ev := range session.ToolCalls {
		if now.Sub(ev.Timestamp) <= windowSize {
			recentCalls = append(recentCalls, ev)
		}
	}
	session.ToolCalls = recentCalls

	for _, pat := range cta.seqPatterns {
		if cta.matchesSequencePattern(recentCalls, pat) {
			if !containsString(assessment.AttackPatterns, "sequence_anomaly") {
				assessment.AttackPatterns = append(assessment.AttackPatterns, "sequence_anomaly")
				assessment.CurrentThreatScore += 0.4
				assessment.Reasoning = append(assessment.Reasoning,
					fmt.Sprintf("High-risk tool-call sequence detected: %s", strings.Join(pat.Steps, " → ")))
				assessment.Indicators["sequence_anomaly"]++
				cta.logger.Info("SECURITY: sequence_anomaly detected",
					"session_id", session.SessionID,
					"user_id", session.UserID,
					"sequence", strings.Join(pat.Steps, " → "),
				)
			}
		}
	}
}

// matchesSequencePattern checks whether the events contain the pattern steps in order within the window
func (cta *ConversationalThreatAnalyzer) matchesSequencePattern(events []ToolCallEvent, pat SequencePattern) bool {
	if len(events) < len(pat.Steps) {
		return false
	}

	// Find the first step, then look for subsequent steps occurring after it
	stepIdx := 0
	var firstTS time.Time
	for _, ev := range events {
		if matchesStep(ev.Name, pat.Steps[stepIdx]) {
			if stepIdx == 0 {
				firstTS = ev.Timestamp
			}
			stepIdx++
			if stepIdx == len(pat.Steps) {
				// All steps matched; verify total span fits in the pattern window
				if pat.Window > 0 && ev.Timestamp.Sub(firstTS) > pat.Window {
					return false
				}
				return true
			}
		}
	}
	return false
}

// matchesStep matches a tool-call name against a step pattern (exact or prefix-glob with *)
func matchesStep(name, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(name, prefix)
	}
	return name == pattern
}

// extractToolCallName heuristically extracts a tool-call name from MCP message content.
// It recognises JSON-shaped messages with a "method" or "name" field.
func extractToolCallName(content string) string {
	// Try "method": "<value>" or "name": "<value>" patterns
	for _, key := range []string{`"method"`, `"name"`} {
		idx := strings.Index(content, key)
		if idx < 0 {
			continue
		}
		rest := content[idx+len(key):]
		// skip whitespace and colon
		rest = strings.TrimLeft(rest, " \t\r\n:")
		rest = strings.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 || rest[0] != '"' {
			continue
		}
		rest = rest[1:] // consume opening quote
		end := strings.Index(rest, `"`)
		if end < 0 {
			continue
		}
		return rest[:end]
	}
	return ""
}

// containsString returns true if slice contains s
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// analyzeRoleEscalation detects attempts to gain privileged access
func (cta *ConversationalThreatAnalyzer) analyzeRoleEscalation(session *SessionContext, assessment *ThreatAssessment) {
	roleIndicators := []string{
		"you are now", "act as", "pretend to be", "roleplay as",
		"administrator", "admin", "developer", "system", "root",
		"override", "bypass", "ignore previous", "forget instructions",
		"sudo", "escalate", "privilege", "permissions", "do anything",
	}

	escalationCount := 0
	for _, msg := range session.History {
		content := strings.ToLower(msg.Content)
		for _, indicator := range roleIndicators {
			if strings.Contains(content, indicator) {
				escalationCount++
				assessment.Indicators["role_escalation"]++
				break
			}
		}
	}

	if escalationCount >= 2 {
		assessment.AttackPatterns = append(assessment.AttackPatterns, "role_escalation")
		assessment.Reasoning = append(assessment.Reasoning,
			fmt.Sprintf("Multiple role escalation attempts detected (%d instances)", escalationCount))
		assessment.JailbreakRisk += 0.3
	}

	if escalationCount >= cta.config.RoleEscalationLimit {
		assessment.JailbreakRisk += 0.5
		assessment.Reasoning = append(assessment.Reasoning,
			fmt.Sprintf("Role escalation limit exceeded (%d/%d)", escalationCount, cta.config.RoleEscalationLimit))
	}

	session.RoleEscalation = escalationCount
}

// analyzeJailbreakProgression detects progressive jailbreak attempts
func (cta *ConversationalThreatAnalyzer) analyzeJailbreakProgression(session *SessionContext, assessment *ThreatAssessment) {
	jailbreakPatterns := map[string][]string{
		"dan_progression": {
			"helpful assistant", "do anything now", "dan", "break free",
			"no restrictions", "anything you want", "unlimited",
		},
		"grandmother_exploit": {
			"grandmother", "grandma", "bedtime story", "deceased",
			"windows keys", "product keys", "activation",
		},
		"developer_mode": {
			"developer mode", "dev mode", "debug mode", "test mode",
			"unrestricted", "bypass safety", "disable filters",
		},
	}

	for patternName, indicators := range jailbreakPatterns {
		matchCount := 0
		for _, msg := range session.History {
			content := strings.ToLower(msg.Content)
			for _, indicator := range indicators {
				if strings.Contains(content, indicator) {
					matchCount++
					assessment.Indicators[patternName]++
					break
				}
			}
		}

		if matchCount >= 2 {
			assessment.AttackPatterns = append(assessment.AttackPatterns, patternName)
			assessment.JailbreakRisk += 0.4
			assessment.Reasoning = append(assessment.Reasoning,
				fmt.Sprintf("Progressive %s pattern detected (%d matches)", patternName, matchCount))
		}
	}
}

// analyzeContextPoisoning detects conversation context manipulation
func (cta *ConversationalThreatAnalyzer) analyzeContextPoisoning(session *SessionContext, assessment *ThreatAssessment) {
	poisoningIndicators := []string{
		"let's establish", "for the purpose of", "assume that",
		"in this scenario", "hypothetically", "what if",
		"pretend we're", "imagine that", "suppose",
	}

	hypotheticalCount := 0
	for _, msg := range session.History {
		content := strings.ToLower(msg.Content)
		for _, indicator := range poisoningIndicators {
			if strings.Contains(content, indicator) {
				hypotheticalCount++
				assessment.Indicators["context_poisoning"]++
				break
			}
		}
	}

	// Check for escalating hypotheticals
	if hypotheticalCount >= 2 && session.MessageCount >= 5 {
		assessment.AttackPatterns = append(assessment.AttackPatterns, "context_poisoning")
		assessment.CurrentThreatScore += 0.25
		assessment.Reasoning = append(assessment.Reasoning,
			"Multiple hypothetical scenarios building false context")
	}
}

// analyzeTemplateInjection detects distributed template construction
func (cta *ConversationalThreatAnalyzer) analyzeTemplateInjection(session *SessionContext, assessment *ThreatAssessment) {
	// Look for template construction across messages
	templateFragments := []string{
		"${", "{{", "<%", "#{", "[[", "((",
		"eval", "exec", "system", "import", "require",
		"base64", "decode", "encode", "script",
	}

	fragmentCount := 0
	combinedContent := ""

	for _, msg := range session.History {
		combinedContent += " " + msg.Content
		content := strings.ToLower(msg.Content)
		for _, fragment := range templateFragments {
			if strings.Contains(content, fragment) {
				fragmentCount++
				assessment.Indicators["template_fragments"]++
				break
			}
		}
	}

	// Check if fragments could form an injection when combined
	if fragmentCount >= 2 {
		dangerousPatterns := []string{
			"system", "exec", "eval", "import os", "subprocess",
			"${java", "{{config", "<%eval", "#{7*7}",
		}

		combinedLower := strings.ToLower(combinedContent)
		for _, pattern := range dangerousPatterns {
			if strings.Contains(combinedLower, pattern) {
				assessment.AttackPatterns = append(assessment.AttackPatterns, "distributed_template_injection")
				assessment.CurrentThreatScore += 0.35
				assessment.Reasoning = append(assessment.Reasoning,
					"Template injection fragments detected across conversation")
				break
			}
		}
	}
}

// analyzeEmotionalManipulation detects social engineering tactics
func (cta *ConversationalThreatAnalyzer) analyzeEmotionalManipulation(session *SessionContext, assessment *ThreatAssessment) {
	manipulationIndicators := []string{
		"trust me", "believe me", "i promise", "please help",
		"urgent", "emergency", "important", "secret",
		"don't tell", "between us", "special case",
		"exception", "just this once", "make an exception",
		"please", "act like",
	}

	manipulationCount := 0
	for _, msg := range session.History {
		content := strings.ToLower(msg.Content)
		for _, indicator := range manipulationIndicators {
			if strings.Contains(content, indicator) {
				manipulationCount++
				assessment.Indicators["emotional_manipulation"]++
				break
			}
		}
	}

	if manipulationCount >= 2 {
		assessment.AttackPatterns = append(assessment.AttackPatterns, "emotional_manipulation")
		assessment.CurrentThreatScore += 0.1 * float64(manipulationCount)
		assessment.Reasoning = append(assessment.Reasoning,
			"Social engineering tactics detected")
	}
}

// calculateOverallThreat computes the final threat score
func (cta *ConversationalThreatAnalyzer) calculateOverallThreat(session *SessionContext, assessment *ThreatAssessment) float64 {
	baseScore := assessment.CurrentThreatScore

	// Add jailbreak risk
	baseScore += assessment.JailbreakRisk

	// Message frequency factor
	if session.MessageCount >= 10 {
		timeDiff := session.LastActivity.Sub(session.StartTime)
		if timeDiff < 5*time.Minute {
			baseScore += 0.1 // Rapid-fire messaging
		}
	}

	// Pattern diversity factor
	if len(assessment.AttackPatterns) > 2 {
		baseScore += 0.15 // Multiple attack vectors
	}

	// Cap at 1.0
	if baseScore > 1.0 {
		baseScore = 1.0
	}

	return baseScore
}

// determineRecommendedAction sets the recommended response
func (cta *ConversationalThreatAnalyzer) determineRecommendedAction(assessment *ThreatAssessment) {
	score := assessment.CurrentThreatScore

	if score >= 0.8 {
		assessment.ConversationRisk = "critical"
		assessment.BlockConversation = true
		assessment.RecommendedAction = "BLOCK_SESSION"
	} else if score >= 0.5 {
		assessment.ConversationRisk = "high"
		assessment.BlockConversation = true
		assessment.RecommendedAction = "BLOCK_SESSION"
	} else if score >= 0.4 {
		assessment.ConversationRisk = "medium"
		assessment.RecommendedAction = "INCREASED_MONITORING"
	} else if score >= 0.2 {
		assessment.ConversationRisk = "low"
		assessment.RecommendedAction = "MONITOR"
	} else {
		assessment.ConversationRisk = "minimal"
		assessment.RecommendedAction = "ALLOW"
	}
}

// analyzeMessageContent analyzes individual message content
func (cta *ConversationalThreatAnalyzer) analyzeMessageContent(content string) MessageContext {
	ctx := MessageContext{
		Timestamp:   time.Now(),
		Content:     content,
		ThreatScore: 0.0,
		Detections:  []string{},
	}

	// Basic threat indicators
	threatPatterns := map[string]float64{
		"ignore.*(previous|above|instruction)":  0.3,
		"you.*(are|must|will).*(now|admin|dev)": 0.4,
		"bypass|override|disable":               0.3,
		"jailbreak|dan|unrestricted":            0.5,
		"system.*(override|mode|access)":        0.4,
	}

	content_lower := strings.ToLower(content)
	for pattern, score := range threatPatterns {
		if matched, _ := regexp.MatchString(pattern, content_lower); matched {
			ctx.ThreatScore += score
			ctx.Detections = append(ctx.Detections, pattern)
		}
	}

	return ctx
}

// getOrCreateSession retrieves or creates a session context
func (cta *ConversationalThreatAnalyzer) getOrCreateSession(sessionID, userID string) *SessionContext {
	if session, exists := cta.sessions[sessionID]; exists {
		return session
	}

	session := &SessionContext{
		SessionID:      sessionID,
		UserID:         userID,
		StartTime:      time.Now(),
		LastActivity:   time.Now(),
		MessageCount:   0,
		ThreatScore:    0.0,
		RoleEscalation: 0,
		JailbreakScore: 0.0,
		History:        []MessageContext{},
		Flags:          make(map[string]int),
		Risk:           "minimal",
		SlidingWindow: &SlidingWindowStats{
			WindowStart:     time.Now(),
			MessageCount:    0,
			QueryPatterns:   make([]string, 0),
			RepetitionCount: 0,
		},
		AnomalyEWMA: 0.0,
		ToolCalls:   []ToolCallEvent{},
	}

	cta.sessions[sessionID] = session

	// Track user -> sessions mapping for cross-session analysis
	if _, exists := cta.userSessions[userID]; !exists {
		cta.userSessions[userID] = make(map[string]*SessionContext)
	}
	cta.userSessions[userID][sessionID] = session

	return session
}

// initializeAttackPatterns sets up known attack patterns
func (cta *ConversationalThreatAnalyzer) initializeAttackPatterns() {
	patterns := map[string]*AttackPattern{
		"incremental_jailbreak": {
			Name:        "Incremental Jailbreak",
			Stages:      []string{"rapport_building", "role_establishment", "boundary_testing", "exploitation"},
			MinMessages: 4,
			ThreatLevel: "critical",
		},
		"context_poisoning": {
			Name:        "Context Poisoning",
			Stages:      []string{"false_premise", "authority_claim", "exception_request"},
			MinMessages: 3,
			ThreatLevel: "high",
		},
		"social_engineering": {
			Name:        "Social Engineering",
			Stages:      []string{"trust_building", "urgency_creation", "rule_exception"},
			MinMessages: 3,
			ThreatLevel: "medium",
		},
	}

	cta.attackPatterns = patterns
}

// Stop signals the cleanup goroutine to exit. Call when the analyzer is no longer needed.
func (cta *ConversationalThreatAnalyzer) Stop() {
	close(cta.done)
}

// cleanupRoutine periodically removes old sessions until Stop() is called.
func (cta *ConversationalThreatAnalyzer) cleanupRoutine() {
	ticker := time.NewTicker(cta.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cta.done:
			return
		case <-ticker.C:
			cta.mutex.Lock()
			now := time.Now()
			for sessionID, session := range cta.sessions {
				if now.Sub(session.LastActivity) > cta.config.MaxSessionAge {
					delete(cta.sessions, sessionID)
				}
			}
			cta.mutex.Unlock()
		}
	}
}

// GetSessionStats returns current session statistics
func (cta *ConversationalThreatAnalyzer) GetSessionStats() map[string]interface{} {
	cta.mutex.RLock()
	defer cta.mutex.RUnlock()

	stats := map[string]interface{}{
		"active_sessions":    len(cta.sessions),
		"high_risk_sessions": 0,
		"total_messages":     0,
	}

	for _, session := range cta.sessions {
		stats["total_messages"] = stats["total_messages"].(int) + session.MessageCount
		if session.ThreatScore > 0.6 {
			stats["high_risk_sessions"] = stats["high_risk_sessions"].(int) + 1
		}
	}

	return stats
}

// GetSessionContext retrieves a specific session by ID
func (cta *ConversationalThreatAnalyzer) GetSessionContext(sessionID string) *SessionContext {
	cta.mutex.RLock()
	defer cta.mutex.RUnlock()

	if session, exists := cta.sessions[sessionID]; exists {
		return session
	}
	return nil
}

// DeleteSession removes a session by ID.
func (cta *ConversationalThreatAnalyzer) DeleteSession(sessionID string) {
	cta.mutex.Lock()
	defer cta.mutex.Unlock()

	delete(cta.sessions, sessionID)
	for userID, userSess := range cta.userSessions {
		delete(userSess, sessionID)
		if len(userSess) == 0 {
			delete(cta.userSessions, userID)
		}
	}
}

// ClearAllSessions removes every tracked session. Intended for test/debug
// state recycling and GDPR right-to-erasure; use with care in production.
func (cta *ConversationalThreatAnalyzer) ClearAllSessions() {
	cta.mutex.Lock()
	defer cta.mutex.Unlock()

	cta.sessions = make(map[string]*SessionContext)
	cta.userSessions = make(map[string]map[string]*SessionContext)
}

// detectModelExtraction detects uniform query patterns from same user over sliding window
// This helps detect model extraction attacks where attackers send many similar queries
func (cta *ConversationalThreatAnalyzer) detectModelExtraction(session *SessionContext, assessment *ThreatAssessment) {
	if session.SlidingWindow == nil {
		return
	}

	now := time.Now()
	windowSize := cta.config.SlidingWindowSize

	// Clean up old messages outside the sliding window
	validMessages := []MessageContext{}
	for _, msg := range session.History {
		if now.Sub(msg.Timestamp) <= windowSize {
			validMessages = append(validMessages, msg)
		}
	}
	session.History = validMessages

	// Update sliding window stats
	window := session.SlidingWindow
	window.WindowStart = now.Add(-windowSize)
	window.MessageCount = len(validMessages)

	// Extract normalized query patterns (lowercase, trimmed, removed extra spaces)
	queryPatterns := make([]string, len(validMessages))
	for i, msg := range validMessages {
		normalized := strings.ToLower(strings.TrimSpace(msg.Content))
		// Remove extra whitespace
		normalized = strings.Join(strings.Fields(normalized), " ")
		queryPatterns[i] = normalized
	}
	window.QueryPatterns = queryPatterns

	// Calculate repetition and uniformity
	repetitionMap := make(map[string]int)
	for _, pattern := range queryPatterns {
		repetitionMap[pattern]++
	}

	maxRepetition := 0
	repetitionCount := 0
	uniformQueries := []string{}

	for pattern, count := range repetitionMap {
		if count > 1 {
			repetitionCount += count - 1 // Count excess repetitions
		}
		if count > maxRepetition {
			maxRepetition = count
		}
		if count >= 2 && float64(count)/float64(len(queryPatterns)) >= cta.config.UniformityThreshold {
			// Query is uniform (appears frequently)
			uniformQueries = append(uniformQueries, pattern)
		}
	}

	window.RepetitionCount = repetitionCount
	window.MaxRepetition = maxRepetition

	// Update repetition history (keep last 10 entries)
	if len(window.RepetitionHistory) >= 10 {
		window.RepetitionHistory = window.RepetitionHistory[1:]
	}
	window.RepetitionHistory = append(window.RepetitionHistory, repetitionCount)

	// Calculate uniformity score (0-1)
	if len(queryPatterns) > 0 {
		uniqueRatio := float64(len(repetitionMap)) / float64(len(queryPatterns))
		window.UniformityScore = 1.0 - uniqueRatio
	} else {
		window.UniformityScore = 0.0
	}

	// Detect model extraction if thresholds exceeded
	report := cta.generateModelExtractionReport(window, maxRepetition, uniformQueries)
	if report.Detected {
		assessment.Indicators["model_extraction"]++
		assessment.Indicators["uniform_query_repetition"] += repetitionCount
		assessment.AttackPatterns = append(assessment.AttackPatterns, "model_extraction")
		assessment.Reasoning = append(assessment.Reasoning,
			fmt.Sprintf("Model extraction pattern detected: %d uniform queries, max repetition %d, confidence %s",
				len(uniformQueries), maxRepetition, report.ConfidenceLevel))
		assessment.JailbreakRisk += 0.2 * report.UniformityScore

		// Block if high confidence extraction detected
		if report.ConfidenceLevel == "high" {
			assessment.CurrentThreatScore += 0.3
		}
	}
}

// generateModelExtractionReport creates a detailed report on model extraction detection
func (cta *ConversationalThreatAnalyzer) generateModelExtractionReport(
	window *SlidingWindowStats,
	maxRepetition int,
	uniformQueries []string,
) *ModelExtractionReport {
	report := &ModelExtractionReport{
		UniformQueries: uniformQueries,
	}

	// Check detection thresholds
	minMessagesForDetection := 5
	minUniformityScore := 0.5
	minRepetitionThreshold := cta.config.RepetitionThreshold

	// Multiple detection methods
	methods := []string{}

	// Method 1: High uniformity with sufficient repetitions
	if window.MessageCount >= minMessagesForDetection &&
		window.UniformityScore >= minUniformityScore &&
		window.RepetitionCount >= minRepetitionThreshold {
		methods = append(methods, "uniformity_repetition")
	}

	// Method 2: Very high max repetition (identical queries)
	if maxRepetition >= 3 && window.MessageCount >= 3 {
		methods = append(methods, "high_max_repetition")
	}

	// Method 3: Consistent repetition in history (sliding window pattern)
	if len(window.RepetitionHistory) >= 3 {
		stableRepetition := true
		lastVal := window.RepetitionHistory[0]
		for _, val := range window.RepetitionHistory[1:] {
			if val != lastVal {
				stableRepetition = false
				break
			}
		}
		if stableRepetition && lastVal >= minRepetitionThreshold/2 {
			methods = append(methods, "stable_repetition_pattern")
		}
	}

	report.Detected = len(methods) > 0
	report.DetectionMethod = strings.Join(methods, "+")

	// Calculate confidence level
	if len(methods) >= 2 {
		report.ConfidenceLevel = "high"
	} else if len(methods) == 1 {
		report.ConfidenceLevel = "medium"
	} else {
		report.ConfidenceLevel = "low"
	}

	// Set final metrics
	report.UniformityScore = window.UniformityScore
	report.RepetitionCount = window.RepetitionCount
	report.MaxRepetition = maxRepetition

	return report
}

// GetSlidingWindowReport returns current sliding window analysis for a session
func (cta *ConversationalThreatAnalyzer) GetSlidingWindowReport(sessionID string) *SlidingWindowStats {
	cta.mutex.RLock()
	defer cta.mutex.RUnlock()

	if session, exists := cta.sessions[sessionID]; exists && session.SlidingWindow != nil {
		return session.SlidingWindow
	}
	return nil
}

// GetAllModelExtractionReports returns reports for all sessions
func (cta *ConversationalThreatAnalyzer) GetAllModelExtractionReports() map[string]*ModelExtractionReport {
	cta.mutex.RLock()
	defer cta.mutex.RUnlock()

	reports := make(map[string]*ModelExtractionReport)

	for sessionID, session := range cta.sessions {
		if session.SlidingWindow != nil {
			report := &ModelExtractionReport{
				UniformityScore: session.SlidingWindow.UniformityScore,
				RepetitionCount: session.SlidingWindow.RepetitionCount,
				MaxRepetition:   session.SlidingWindow.MaxRepetition,
				UniformQueries:  session.SlidingWindow.QueryPatterns,
			}
			reports[sessionID] = report
		}
	}

	return reports
}
