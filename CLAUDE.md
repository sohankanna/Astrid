# AI Security Hackathon Project

## Mission
Build a working AI-security prototype for the hackathon.

## Development principles
- Prioritize a working MVP over unnecessary complexity.
- Keep the architecture modular.
- Never hardcode API keys or credentials.
- Store secrets in environment variables.
- Validate all external input.
- Treat LLM output as untrusted data.
- Implement authentication/authorization where applicable.
- Log security-relevant events without exposing secrets.
- Prefer simple, explainable security controls.
- Test security-sensitive functionality explicitly.

## Project structure
- app/ = application source
- architecture/ = architecture and design artifacts
- docs/ = documentation
- research/ = research material
- security/ = threat model and security analysis
- scripts/ = utility scripts
- tests/ = automated tests
- prompts/ = prompts and adversarial test cases
- data/ = datasets and test data
- notes/ = working notes

## Coding rules
- Use Python type hints.
- Keep functions small and testable.
- Handle errors explicitly.
- Do not silently swallow exceptions.
- Do not introduce dependencies without explaining why.
- Run tests after meaningful changes.
- Keep security controls close to the functionality they protect.

## AI security
Consider:
- prompt injection
- indirect prompt injection
- insecure tool use
- excessive agency
- sensitive information disclosure
- improper output handling
- authentication/authorization failures
- data poisoning where relevant
- model/API abuse
- rate limiting
- SSRF where applicable
- malicious file/document input
- insecure integrations

## Workflow
Before implementing major functionality:
1. Understand the requirement.
2. Identify the threat model.
3. Propose the architecture.
4. Identify security boundaries.
5. Implement the smallest viable version.
6. Test it.
7. Review the implementation for security issues.

Do not rewrite working code unnecessarily.
