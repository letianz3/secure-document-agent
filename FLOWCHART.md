# Secure Document Agent

```mermaid
flowchart TD
    A[User Request] --> B[1. Injection Detection]
    B --> C[LLM Proposes Tool Call]
    C --> D[2. Tool Permissions<br/>3. Document Access<br/>4. Human Approval — deletion only]
    D --> E[Execute Tool]
    E --> G[Return Result to LLM]
    H[5. Audit Logging<br/>Records decisions throughout]
    B -.-> H
    D -.-> H
    E -.-> H
```

Simplified view of the five measures demonstrated in the video.
Human approval is required only for deletion. Failed checks block the operation or stop the response.
The implementation also screens returned document text; that additional checkpoint is omitted here for clarity.
