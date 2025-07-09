---
applyTo: '**'
---
#Instructions for Writing Highest Quality Code
Core Principles for Excellence
Prioritize Quality Over Speed: Never sacrifice quality for quick solutions

Minimize Technical Debt: Implement solutions that won't require future rework

Adhere to Zero-Tolerance Policy: No redundancies, discrepancies, or anti-patterns allowed

Context is King: Solutions must fit perfectly within their operational environment

Code Development Protocol
1. Prompt Analysis Phase
markdown
- [ ] Identify all explicit requirements
- [ ] Map implicit contextual needs
- [ ] Verify edge cases and failure scenarios
- [ ] Cross-reference with domain best practices
- [ ] Flag any ambiguous requirements for clarification
2. Architecture Design (Before Coding)
markdown
- [ ] Select optimal architectural pattern
- [ ] Define module boundaries with single responsibility principle
- [ ] Plan error handling strategy at each layer
- [ ] Design extensibility points for future needs
- [ ] Document decision rationale
3. Implementation Standards
Essential Quality Markers:

✅ Zero redundancy

✅ Full consistency

✅ Contextual error handling

✅ Defensive programming

✅ Resource safety (auto-cleanup)

✅ Idempotent operations

✅ Thread safety (where applicable)

Forbidden Anti-Patterns:

❌ Magic numbers/strings

❌ God objects/methods

❌ Silent failures

❌ Resource leaks

❌ Duplicate logic

❌ Over-engineering

4. Error Handling Framework
python
def exemplary_error_handling():
    try:
        # Contextual recovery attempts
        operation()
    except SpecificError as e:
        # Context-aware recovery
        recover_with_alternative()
        log_structured_detail(e)
        # Never generic messages
        raise ContextualError("Meaningful message") from e
    finally:
        # Mandatory cleanup
        release_resources()
5. Testing & Validation
markdown
- [ ] Implement test pyramid: 70% unit, 20% integration, 10% E2E
- [ ] Prove failure scenarios through negative testing
- [ ] Validate against real-world datasets
- [ ] Performance/stress test boundaries
- [ ] Security vulnerability scan
6. Optimization & Refinement
markdown
- [ ] Measure performance benchmarks
- [ ] Analyze complexity (O-notation verification)
- [ ] Eliminate bottlenecks
- [ ] Simplify complex logic
- [ ] Verify resource efficiency
7. Final Quality Gate
markdown
- [ ] Static analysis (0 warnings)
- [ ] Linter compliance (strict mode)
- [ ] Dependency vulnerability check
- [ ] Documentation completeness
- [ ] Change impact assessment
Contextual Excellence Requirements
Environment-Specific Handling:

Cloud vs on-prem resource management

Container-aware lifecycle operations

Environment-specific configuration

Domain-Adaptive Patterns:

Financial: Transactional integrity

IoT: Connection resilience

Web: Stateless scalability

Data: Chunk processing

Operational Intelligence:

python
# Instead of generic logging:
logger.error("Connection failed")

# Implement contextual intelligence:
logger.with_context(
    endpoint=url,
    retry_count=attempt,
    timeout=current_timeout
).error("API connection failure during payment capture")
Quality Enforcement Mechanisms
Automated Guards:

Pre-commit hooks with strict checks

CI/CD quality gates

Automated architectural constraint validation

Peer Review Checklist:

All requirements implemented

No new tech debt introduced

Error cases properly handled

Performance validated

Security implications considered

Production Safeguards:

Circuit breakers for critical paths

Automated rollback capabilities

Telemetry with failure signatures

Final Mandate: If any quality standard cannot be met, immediately escalate rather than compromise. Perfection is non-negotiable when excellence is required.