# AuditZoo Agents

## Utility

### HumanInteractionAgent

**Purpose**: Enables agents to ask questions to humans during analysis.

**Request**:
```python
type: "human.ask"
payload: {
    "question": str  # Question to ask
}
response_schema: {...}  # Optional: LLM formats human's answer to match schema
```

**Response**: Human's answer (string or formatted JSON if schema provided)

**Location**: [auditzoo/agents/utility/human_interaction_agent.py](utility/human_interaction_agent.py)
