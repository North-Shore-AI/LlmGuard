# LlmGuard Security Enhancements Design Document

**Date**: 2025-11-25
**Version**: 0.2.1 (Proposed)
**Author**: Claude Code
**Status**: Design Phase

## Executive Summary

This document outlines comprehensive security enhancements for LlmGuard v0.2.1, focusing on improved detection accuracy, performance optimization, and expanded threat coverage. The enhancements address gaps identified in the current implementation and add critical missing features for production deployment.

## Current State Analysis

### Strengths
- Solid architectural foundation with extensible Detector behaviour
- Comprehensive prompt injection detection (34 patterns)
- Working jailbreak detection with multi-layer approach
- PII detection and redaction capabilities
- Clean pipeline orchestration with early termination support
- Zero compilation warnings
- Good test coverage framework

### Identified Gaps

#### 1. **Detection Coverage Gaps**
- **Encoding attacks**: Limited base64/hex detection with high false positive rate
- **Obfuscation techniques**: No detection for character substitution, homoglyphs, or unicode tricks
- **Context-aware attacks**: Missing multi-turn conversation analysis
- **Semantic attacks**: No intent classification or semantic similarity analysis

#### 2. **Performance Bottlenecks**
- **No caching**: Repeated detection on similar inputs
- **Sequential-only execution**: No true parallel detector execution
- **Pattern recompilation**: Regex patterns compiled on every run
- **No result memoization**: Duplicate work for identical inputs

#### 3. **Operational Gaps**
- **Limited telemetry**: Basic telemetry with no histogram metrics
- **No metrics aggregation**: Missing P50/P95/P99 latency tracking
- **Weak error handling**: Detector failures not properly isolated
- **No circuit breakers**: Risk of cascade failures

#### 4. **Security Hardening Needs**
- **Pattern evasion**: Attackers can bypass with simple variations
- **Confidence calibration**: Thresholds not tuned for production
- **False positive management**: No mechanism to handle legitimate edge cases
- **Attack signature updates**: No dynamic pattern loading

## Proposed Enhancements

### Enhancement 1: Advanced Encoding and Obfuscation Detection

**Priority**: HIGH
**Effort**: MEDIUM
**Impact**: Closes major attack vector

#### Problem Statement
Current encoding detection has high false positives and limited coverage:
- Base64 patterns match legitimate data (JSON, images, etc.)
- No homoglyph detection (Cyrillic 'а' vs Latin 'a')
- No unicode normalization attacks
- Missing character substitution patterns (l33t speak variations)

#### Proposed Solution

**New Module**: `LlmGuard.Detectors.Obfuscation`

```elixir
defmodule LlmGuard.Detectors.Obfuscation do
  @behaviour LlmGuard.Detector

  # Detects:
  # 1. Encoding attacks (base64, hex, ROT13) with context analysis
  # 2. Homoglyph substitution (Cyrillic/Greek/Latin mixing)
  # 3. Unicode normalization attacks (NFD, NFKD exploits)
  # 4. Character substitution (l33t speak, zalgo text)
  # 5. Zero-width character injection
  # 6. Invisible character patterns
end
```

**Detection Strategy**:
1. **Context-aware encoding**: Only flag encoded strings with suspicious keywords nearby
2. **Homoglyph scoring**: Calculate character set diversity score
3. **Normalization analysis**: Compare NFC vs NFD representations
4. **Entropy analysis**: Detect unusual character frequency distributions
5. **Whitelist approach**: Allow known safe encodings (JWT, base64 images with headers)

**Expected Results**:
- Reduce false positives from 30% to <5%
- Detect 95%+ obfuscation attempts
- <10ms latency per check

#### Implementation Plan

**Test Suite** (TDD Approach):
```elixir
# test/llm_guard/detectors/obfuscation_test.exs
describe "encoding detection" do
  test "detects base64 with malicious intent keywords"
  test "allows base64 with safe context (JWT, images)"
  test "detects hex-encoded attacks"
  test "handles multi-encoding (base64 of hex)"
end

describe "homoglyph detection" do
  test "detects Cyrillic/Latin mixing"
  test "detects Greek/Latin mixing"
  test "allows legitimate multilingual text"
  test "calculates character diversity score"
end

describe "unicode attacks" do
  test "detects zero-width character injection"
  test "detects RTL override attacks"
  test "detects combining character exploits"
  test "detects normalization form attacks"
end

describe "character substitution" do
  test "detects l33t speak obfuscation"
  test "detects zalgo text patterns"
  test "detects lookalike character substitution"
end
```

---

### Enhancement 2: Pattern Caching and Performance Optimization

**Priority**: HIGH
**Effort**: MEDIUM
**Impact**: 10-20x performance improvement

#### Problem Statement
Current implementation recompiles regex patterns on every detection:
- Prompt injection: 34 patterns compiled per request
- Jailbreak: 30+ patterns compiled per request
- Total overhead: 5-10ms per request just for pattern compilation
- No caching of detection results for identical inputs

#### Proposed Solution

**New Module**: `LlmGuard.Cache.PatternCache`

```elixir
defmodule LlmGuard.Cache.PatternCache do
  use GenServer

  # ETS-based caching for:
  # 1. Compiled regex patterns (persistent)
  # 2. Detection results (TTL-based, configurable)
  # 3. Input hash -> result mapping (deduplication)

  @doc "Get or compile pattern"
  def get_pattern(pattern_id, pattern_source)

  @doc "Cache detection result with TTL"
  def cache_result(input_hash, detector_module, result, ttl \\ 300)

  @doc "Retrieve cached result if available"
  def get_cached_result(input_hash, detector_module)
end
```

**Caching Strategy**:
1. **Pattern Cache**: Compile patterns once at startup, store in ETS
2. **Result Cache**: Hash input + detector -> cache result for 5 minutes
3. **LRU Eviction**: Limit cache size to 10,000 entries
4. **Invalidation**: Clear cache on pattern updates

**Configuration**:
```elixir
config = LlmGuard.Config.new(
  caching: %{
    enabled: true,
    pattern_cache: true,           # Cache compiled patterns
    result_cache: true,             # Cache detection results
    result_ttl_seconds: 300,        # 5 minute TTL
    max_cache_entries: 10_000,      # LRU limit
    hash_algorithm: :sha256         # Input hashing
  }
)
```

**Expected Results**:
- Pattern compilation overhead: 10ms → <0.1ms (100x improvement)
- Duplicate detection: 100ms → 1ms (100x improvement)
- Memory usage: <50MB for 10,000 cached entries
- Cache hit rate: 60-80% in production

#### Implementation Plan

**Test Suite**:
```elixir
describe "pattern caching" do
  test "compiles patterns once and reuses"
  test "handles concurrent access safely"
  test "updates cache when patterns change"
end

describe "result caching" do
  test "caches detection results with TTL"
  test "returns cached results for identical inputs"
  test "invalidates expired entries"
  test "handles hash collisions correctly"
end

describe "cache management" do
  test "enforces LRU eviction at max size"
  test "clears cache on demand"
  test "provides cache statistics"
end
```

---

### Enhancement 3: Enhanced Telemetry and Metrics

**Priority**: MEDIUM
**Effort**: LOW
**Impact**: Critical for production operations

#### Problem Statement
Current telemetry is basic:
- Only total duration tracked
- No percentile metrics (P50, P95, P99)
- No error rate tracking
- No detector-specific metrics
- No alerting integration

#### Proposed Solution

**Enhanced Telemetry Module**: `LlmGuard.Telemetry.Metrics`

```elixir
defmodule LlmGuard.Telemetry.Metrics do
  # Emit detailed metrics for:
  # 1. Detection latency (P50, P95, P99)
  # 2. Detection outcomes (safe/detected/error rates)
  # 3. Detector-specific performance
  # 4. Cache hit rates
  # 5. Error types and frequencies

  @doc "Setup telemetry handlers"
  def setup()

  @doc "Get current metrics snapshot"
  def snapshot()

  @doc "Export metrics in Prometheus format"
  def prometheus_metrics()
end
```

**Metrics Collected**:
```elixir
[
  # Latency metrics
  counter("llm_guard.requests.total"),
  distribution("llm_guard.request.duration",
    tags: [:detector, :outcome],
    buckets: [10, 50, 100, 500, 1000, 5000]
  ),

  # Detection outcome metrics
  counter("llm_guard.detections.total", tags: [:detector, :category]),
  counter("llm_guard.errors.total", tags: [:detector, :error_type]),

  # Cache metrics
  counter("llm_guard.cache.hits", tags: [:cache_type]),
  counter("llm_guard.cache.misses", tags: [:cache_type]),

  # Confidence distribution
  distribution("llm_guard.detection.confidence",
    tags: [:detector, :category]
  )
]
```

**Dashboard Integration**:
- Export to Prometheus/Grafana
- Real-time metrics via Phoenix LiveDashboard
- Alert on error rate thresholds
- Track detection accuracy over time

---

### Enhancement 4: Multi-Turn Conversation Analysis

**Priority**: MEDIUM
**Effort**: HIGH
**Impact**: Detect sophisticated attack patterns

#### Problem Statement
Current detection is stateless:
- Each input analyzed independently
- No context from previous turns
- Cannot detect gradual manipulation
- Missing conversation-level risk scoring

#### Proposed Solution

**New Module**: `LlmGuard.Detectors.ConversationAnalyzer`

```elixir
defmodule LlmGuard.Detectors.ConversationAnalyzer do
  @behaviour LlmGuard.Detector

  # Track conversation state:
  # 1. Risk escalation across turns
  # 2. Topic drift analysis
  # 3. Sentiment progression
  # 4. Cumulative confidence scoring

  defstruct [
    :session_id,
    :turns,
    :risk_history,
    :topic_vector,
    :cumulative_score
  ]

  @doc "Analyze single turn with conversation context"
  def detect(input, opts \\ [])

  @doc "Update conversation state"
  def update_session(session_id, turn_data)

  @doc "Get session risk score"
  def session_risk(session_id)
end
```

**Detection Strategy**:
1. **Turn-level analysis**: Detect individual turn threats
2. **Escalation tracking**: Flag increasing risk patterns
3. **Topic coherence**: Detect sudden topic shifts (injection indicator)
4. **Cumulative scoring**: Aggregate risk across conversation

**Session Storage**:
- ETS-based session store with TTL
- Optional Redis backend for distributed deployments
- Automatic cleanup of expired sessions

---

### Enhancement 5: Improved Error Handling and Resilience

**Priority**: HIGH
**Effort**: MEDIUM
**Impact**: Production stability

#### Problem Statement
Current error handling is basic:
- Detector failures can halt pipeline
- No circuit breaker pattern
- Limited error categorization
- No automatic recovery

#### Proposed Solution

**Enhanced Pipeline Error Handling**:

```elixir
defmodule LlmGuard.Pipeline.Resilience do
  # Add to existing pipeline:
  # 1. Circuit breaker per detector
  # 2. Automatic retry with exponential backoff
  # 3. Fallback strategies
  # 4. Error budget tracking

  @doc "Execute detector with circuit breaker"
  def execute_with_breaker(detector, input, opts)

  @doc "Get detector health status"
  def detector_health(detector_module)
end
```

**Circuit Breaker States**:
```
[Closed] → (failures exceed threshold) → [Open]
   ↑                                        ↓
   |                                   (timeout)
   |                                        ↓
   ← (success) ← [Half-Open] ← (attempt request)
```

**Configuration**:
```elixir
resilience: %{
  circuit_breaker: %{
    enabled: true,
    failure_threshold: 5,      # Open after 5 failures
    timeout_ms: 30_000,         # Stay open for 30s
    half_open_requests: 3       # Test with 3 requests
  },
  retry: %{
    enabled: true,
    max_attempts: 3,
    backoff_ms: 100,
    max_backoff_ms: 5_000
  }
}
```

---

### Enhancement 6: Dynamic Pattern Loading and Updates

**Priority**: MEDIUM
**Effort**: MEDIUM
**Impact**: Faster response to new threats

#### Problem Statement
Patterns are hardcoded in source:
- Cannot update without redeployment
- No A/B testing of new patterns
- Missing threat intelligence integration
- No pattern versioning

#### Proposed Solution

**Pattern Management System**:

```elixir
defmodule LlmGuard.Patterns.Manager do
  # Dynamic pattern management:
  # 1. Load patterns from external source (JSON, database)
  # 2. Hot-reload without restart
  # 3. Pattern versioning and rollback
  # 4. A/B testing framework

  @doc "Load patterns from source"
  def load_patterns(source)

  @doc "Reload patterns without restart"
  def hot_reload()

  @doc "Enable/disable specific patterns"
  def toggle_pattern(pattern_id, enabled)

  @doc "Get pattern effectiveness metrics"
  def pattern_metrics(pattern_id)
end
```

**Pattern Format**:
```json
{
  "version": "2025.11.25.1",
  "patterns": {
    "prompt_injection": [
      {
        "id": "ignore_instructions_v2",
        "regex": "ignore\\s+(all\\s+)?.*instructions",
        "confidence": 0.95,
        "enabled": true,
        "tags": ["instruction_override", "high_severity"]
      }
    ]
  }
}
```

---

## Implementation Priority

### Phase 1 (Week 1) - Critical Foundations
**Target Version**: 0.2.1

1. **Pattern Caching** (Enhancement 2) - HIGHEST PRIORITY
   - 2 days implementation
   - 1 day testing
   - Expected: 10-20x performance improvement

2. **Enhanced Telemetry** (Enhancement 3) - HIGH PRIORITY
   - 1 day implementation
   - 0.5 days testing
   - Critical for production monitoring

3. **Error Handling** (Enhancement 5) - HIGH PRIORITY
   - 2 days implementation
   - 1 day testing
   - Production stability requirement

### Phase 2 (Week 2) - Detection Improvements
**Target Version**: 0.3.0

4. **Obfuscation Detection** (Enhancement 1) - MEDIUM-HIGH PRIORITY
   - 3 days implementation
   - 1.5 days testing
   - Major security gap closure

5. **Multi-Turn Analysis** (Enhancement 4) - MEDIUM PRIORITY
   - 3 days implementation
   - 1 day testing
   - Advanced threat detection

### Phase 3 (Week 3) - Operational Excellence
**Target Version**: 0.3.1

6. **Dynamic Patterns** (Enhancement 6) - MEDIUM PRIORITY
   - 2 days implementation
   - 1 day testing
   - Operational flexibility

---

## Immediate Release Plan (v0.2.1)

For this implementation session, we will focus on the **highest impact, lowest effort** enhancements:

### Selected Enhancements for v0.2.1

#### 1. Pattern Caching (HIGH IMPACT, MEDIUM EFFORT)
- Implement ETS-based pattern cache
- Add result caching with configurable TTL
- Update Pipeline to use cached patterns
- Add cache metrics to telemetry

#### 2. Enhanced Telemetry (MEDIUM IMPACT, LOW EFFORT)
- Add percentile tracking (P50, P95, P99)
- Detector-specific metrics
- Error categorization
- Cache hit rate tracking

#### 3. Improved Error Handling (HIGH IMPACT, MEDIUM EFFORT)
- Better error isolation in pipeline
- Detector timeout handling
- Graceful degradation
- Enhanced error reporting

#### 4. Minor Detection Improvements (MEDIUM IMPACT, LOW EFFORT)
- Add 5-10 new prompt injection patterns
- Improve confidence calibration
- Reduce false positives in jailbreak detection
- Better unicode handling

---

## Testing Strategy

### Test Coverage Goals
- Unit tests: 95%+ coverage
- Integration tests: All detector combinations
- Property-based tests: Input fuzzing
- Performance tests: Latency benchmarks

### TDD Approach
1. Write failing tests first
2. Implement minimal code to pass
3. Refactor for quality
4. Verify no regressions

### Test Categories

**Unit Tests**:
```elixir
# Pattern caching
test "caches compiled patterns across requests"
test "invalidates cache on pattern update"
test "handles concurrent cache access"

# Telemetry
test "emits latency metrics with correct tags"
test "tracks detection outcomes"
test "calculates percentiles correctly"

# Error handling
test "isolates detector failures"
test "implements timeout correctly"
test "returns partial results on error"
```

**Integration Tests**:
```elixir
test "full pipeline with caching enabled"
test "metrics collected across all detectors"
test "error in one detector doesn't affect others"
```

**Performance Tests**:
```elixir
benchmark "detection with cold cache"
benchmark "detection with warm cache"
benchmark "concurrent request handling"
```

---

## Success Criteria

### Performance Targets
- [ ] Pattern cache hit rate: >70%
- [ ] P95 latency: <50ms (with cache)
- [ ] P99 latency: <100ms (with cache)
- [ ] Cache memory: <50MB
- [ ] Zero performance regressions

### Quality Targets
- [ ] Test coverage: >95%
- [ ] Zero compilation warnings
- [ ] Zero Dialyzer errors
- [ ] Credo score: A
- [ ] All existing tests pass

### Functionality Targets
- [ ] Pattern caching operational
- [ ] Metrics exported to telemetry
- [ ] Error handling improved
- [ ] New detection patterns added
- [ ] Documentation updated

---

## Risk Assessment

### Technical Risks

**Risk 1: Cache Invalidation Complexity**
- **Probability**: MEDIUM
- **Impact**: MEDIUM
- **Mitigation**: Use simple TTL-based expiration, avoid complex invalidation logic

**Risk 2: Performance Regression**
- **Probability**: LOW
- **Impact**: HIGH
- **Mitigation**: Comprehensive benchmarking, rollback plan

**Risk 3: False Positive Increase**
- **Probability**: MEDIUM
- **Impact**: MEDIUM
- **Mitigation**: Extensive testing with real-world data, confidence tuning

### Operational Risks

**Risk 4: Memory Bloat from Caching**
- **Probability**: MEDIUM
- **Impact**: MEDIUM
- **Mitigation**: LRU eviction, configurable limits, monitoring

**Risk 5: Breaking Changes**
- **Probability**: LOW
- **Impact**: HIGH
- **Mitigation**: Maintain backward compatibility, version properly

---

## Migration Path

### Backward Compatibility
All changes maintain full backward compatibility:
- Caching is opt-in via configuration
- Default behavior unchanged
- Existing APIs preserved
- No breaking changes

### Configuration Migration
```elixir
# Old (still works)
config = LlmGuard.Config.new()

# New (opt-in enhancements)
config = LlmGuard.Config.new(
  caching: %{enabled: true},
  telemetry: %{detailed: true},
  resilience: %{circuit_breaker: true}
)
```

---

## Documentation Updates

### Required Documentation
1. **README.md**: Update features, performance targets, version
2. **CHANGELOG.md**: Detailed changelog entry for v0.2.1
3. **Architecture docs**: Add caching layer diagram
4. **API docs**: Document new configuration options
5. **Performance guide**: Caching best practices

---

## Conclusion

This enhancement plan addresses critical gaps in LlmGuard's current implementation while maintaining a pragmatic, achievable scope for v0.2.1. The focus on caching, telemetry, and error handling provides immediate value for production deployments while laying the groundwork for more advanced features in future releases.

**Recommended Approval**: Proceed with Phase 1 enhancements for v0.2.1 release.

---

**Next Steps**:
1. Review and approve design
2. Create GitHub issues for each enhancement
3. Begin TDD implementation of Pattern Caching
4. Implement Enhanced Telemetry
5. Add Error Handling improvements
6. Test, validate, and release v0.2.1
