# How mikmbr Works

## The Core Concept: Abstract Syntax Tree (AST)

Instead of using regex to search for patterns in text (which is error-prone), we use Python's built-in `ast` module to parse code into a **tree structure** that represents the code's meaning.

### Example: From Code to AST

**Python Code:**
```python
result = eval("1 + 1")
```

**AST Representation:**
```
Module
└── Assign
    ├── targets: [Name(id='result')]
    └── value: Call
        ├── func: Name(id='eval')
        └── args: [Constant(value='1 + 1')]
```

The AST shows:
- This is an assignment (`Assign`)
- Assigning to variable `result`
- The value is a function call (`Call`)
- The function being called is `eval`
- With argument `"1 + 1"`

### Why AST is Better than Regex

**Regex approach (fragile):**
```python
# Would miss these:
result = eval \
    ("1 + 1")  # Line break

x = (
    eval("test")  # Indented differently
)

my_eval = eval  # False positive
```

**AST approach (robust):**
- Understands Python syntax perfectly
- Handles all formatting/whitespace variations
- Distinguishes between function calls and variable names
- Knows the exact line number
- Understands code structure (loops, conditions, etc.)

## Scanner Flow (Step by Step)

### 1. File Discovery
```python
# Scanner.scan_path() in scanner.py
path = Path("myproject/")
for py_file in path.rglob('*.py'):  # Find all .py files recursively
    findings.extend(scan_file(py_file))
```

### 2. Parse to AST
```python
# Scanner.scan_file() in scanner.py
with open("myfile.py") as f:
    source = f.read()

tree = ast.parse(source, filename="myfile.py")
# Now we have an AST tree structure
```

### 3. Walk the Tree
```python
# Each rule walks the entire tree
for node in ast.walk(tree):
    # Visits every node: assignments, function calls, if statements, etc.
    if isinstance(node, ast.Call):  # Found a function call
        # Check if it's dangerous
```

### 4. Pattern Matching

Each rule looks for specific patterns:

**Example: DangerousExecRule**
```python
for node in ast.walk(tree):
    if isinstance(node, ast.Call):  # Is it a function call?
        if isinstance(node.func, ast.Name):  # Direct function name?
            if node.func.id in ('eval', 'exec'):  # Is it eval or exec?
                # FOUND A VULNERABILITY!
                findings.append(Finding(
                    file=filepath,
                    line=node.lineno,  # AST gives us the line number!
                    rule_id="DANGEROUS_EXEC",
                    severity=Severity.HIGH,
                    message=f"Use of {node.func.id}() allows arbitrary code execution",
                    remediation="Avoid eval()..."
                ))
```

**Example: CommandInjectionRule**
```python
# Detect: subprocess.run("cmd", shell=True)
if isinstance(node.func, ast.Attribute):  # Method call (obj.method)
    if node.func.value.id == 'subprocess':  # subprocess module?
        if node.func.attr in ('run', 'call', 'Popen'):  # subprocess.run?
            # Check for shell=True in keyword arguments
            for keyword in node.keywords:
                if keyword.arg == 'shell' and keyword.value.value is True:
                    # FOUND shell=True!
```

### 5. Collect All Findings
```python
all_findings = []
for rule in ALL_RULES:  # Run each detection rule
    findings = rule.check(tree, source, filepath)
    all_findings.extend(findings)
```

### 6. Format Output
```python
formatter = HumanFormatter()  # or JSONFormatter()
output = formatter.format(all_findings)
print(output)
```

## Real Example Walkthrough

Let's trace what happens when we scan this code:

**Input: vulnerable.py**
```python
import os
user_input = input("Enter command: ")
os.system(user_input)
```

**Step 1: Parse to AST**
```
Module
├── Import (line 1)
│   └── names: [alias(name='os')]
├── Assign (line 2)
│   ├── targets: [Name(id='user_input')]
│   └── value: Call
│       ├── func: Name(id='input')
│       └── args: [Constant(value='Enter command: ')]
└── Expr (line 3)
    └── value: Call
        ├── func: Attribute
        │   ├── value: Name(id='os')
        │   └── attr: 'system'
        └── args: [Name(id='user_input')]
```

**Step 2: CommandInjectionRule Walks the Tree**
```python
# Visiting line 1 (Import) - skip
# Visiting line 2 (Assign with input() call) - skip
# Visiting line 3 (Call node)
node = Call(
    func=Attribute(value=Name(id='os'), attr='system'),
    args=[Name(id='user_input')],
    lineno=3
)

# Check: Is this os.system()?
if node.func.value.id == 'os' and node.func.attr == 'system':
    # YES! Found os.system() on line 3
    return Finding(
        file="vulnerable.py",
        line=3,  # From node.lineno
        rule_id="COMMAND_INJECTION",
        severity=Severity.HIGH,
        message="os.system() is vulnerable to command injection",
        remediation="Use subprocess.run() with a list..."
    )
```

**Step 3: Output**
```
[HIGH] vulnerable.py:3
  Rule: COMMAND_INJECTION
  Issue: os.system() is vulnerable to command injection
  Fix: Use subprocess.run() with a list of arguments...
```

## Why This Approach is Powerful

### 1. Accurate
- No false positives from comments or strings
- Understands Python syntax perfectly
- Gets exact line numbers

### 2. Fast
- AST parsing is native Python (written in C)
- Single pass through each file
- No external dependencies

### 3. Extensible
- Easy to add new rules
- Each rule is independent
- Can check for complex patterns

### 4. Comprehensive
- Can detect any pattern in Python code
- Can analyze code structure (nested loops, etc.)
- Can track relationships between nodes

## What Each File Does

### models.py
```python
@dataclass
class Finding:
    file: str      # Which file
    line: int      # Which line
    rule_id: str   # Which rule caught it
    severity: Severity  # How bad is it
    message: str   # What's wrong
    remediation: str  # How to fix it
```

### rules/base.py
```python
class Rule(ABC):
    @abstractmethod
    def check(self, tree: ast.AST, source: str, filepath: str) -> List[Finding]:
        """Each rule implements this to find vulnerabilities"""
        pass
```

### rules/dangerous_exec.py
```python
class DangerousExecRule(Rule):
    def check(self, tree, source, filepath):
        findings = []
        for node in ast.walk(tree):  # Visit every node
            if is_eval_or_exec(node):  # Our detection logic
                findings.append(create_finding(node))
        return findings
```

### scanner.py
```python
class Scanner:
    def scan_file(self, filepath):
        tree = ast.parse(read_file(filepath))  # Parse to AST
        findings = []
        for rule in ALL_RULES:  # Run all rules
            findings.extend(rule.check(tree, source, filepath))
        return findings
```

### formatters.py
```python
class HumanFormatter:
    def format(self, findings):
        # Convert Finding objects to readable text
        return "[HIGH] file.py:10\n  Rule: DANGEROUS_EXEC\n  ..."
```

### cli.py
```python
def main():
    args = parse_args()  # Get command line arguments
    scanner = Scanner()
    findings = scanner.scan_path(args.path)  # Scan
    formatter = get_formatter(args.format)  # Human or JSON
    print(formatter.format(findings))  # Output
    sys.exit(1 if findings else 0)  # Exit code
```

## Key Advantages Over Other Tools

**vs Regex-based scanners:**
- More accurate (understands code structure)
- Fewer false positives
- Handles all formatting variations

**vs Bandit (popular Python security scanner):**
- Similar approach! Both use AST
- mikmbr is simpler and more focused
- Easier to extend and customize
- Better output formats

**vs SonarQube/Semgrep:**
- Lighter weight (no server/database)
- Faster for Python-only projects
- Easier to understand and modify
- Better remediation guidance

## Limitations

**What AST Can't Do:**
1. **Cross-file analysis**: Can't track if function in file A calls dangerous function in file B
2. **Runtime behavior**: Can't tell if code path is actually reachable
3. **Data flow**: Can't track if variable was sanitized before use (without taint analysis)

**Example it can't catch:**
```python
def process(cmd):
    os.system(cmd)  # AST sees os.system()

process("ls")  # But can't tell this is safe
process(user_input)  # And this is dangerous
```

This would require **taint analysis** (tracking data flow), which is planned for v2.0.

## Next Steps: Adding Verbose Mode

Now that you understand how it works, let's add verbose mode which will:
1. Show the actual code snippet from `source` using `node.lineno`
2. Add CWE IDs and OWASP categories to each rule
3. Add confidence levels
4. Include reference links

Ready to implement Option 1?
