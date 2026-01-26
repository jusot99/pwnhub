# OpenSecret Challenge Writeup 🚀

> *"Open secrets are not secrets!"* - The flag that tells you everything

## Challenge Overview 🎯
**Challenge**: OpenSecret (Very Easy - 0 points)  
**Category**: Web / Information Disclosure  
**Tags**: `jwt`, `hardcoded-secrets`, `client-side`, `javascript`

> **A simple help desk portal where users can submit support tickets. The application uses JWT tokens for session management, but something seems off about how they're implemented. Can you find the security flaw?**

## Executive Summary 📝
This challenge demonstrates a **critical security vulnerability** where JWT secrets are exposed in client-side JavaScript code. The flag is literally the exposed secret key itself, teaching the valuable lesson that client-side secrets are never secure.

## The "Aha!" Moment 💡

The moment of realization came within seconds of visiting the page:

1. **View Page Source (Ctrl+U)** - Always the first step!
2. **Spot the smoking gun** in line 134 of the HTML:
   ```javascript
   const SECRET_KEY = "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}";
   ```
3. **Facepalm** 🤦‍♂️ - The vulnerability is literally spelled out in the flag!

## Technical Analysis 🔍

### 1. The Vulnerability: Client-Side JWT Secret Exposure
The application generates JWT tokens **client-side** using Web Crypto API with a hardcoded secret:

```javascript
// ❌ TERRIBLE SECURITY PRACTICE!
const SECRET_KEY = "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}";

function generateJWT() {
    // Creates JWT token in browser (client-side)
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { username: `guest_${randomNumber}` };
    
    // Signs with exposed secret
    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(data)
    );
}
```

### 2. Why This Is Critical 🔴
- **Any user** can see the secret by viewing page source
- **Token forgery** becomes trivial
- **Authentication bypass** is possible
- **Complete compromise** of JWT-based security

### 3. The Irony (and Lesson) 🎓
The flag itself `HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}` perfectly describes the vulnerability. When secrets are "open" (exposed), they're no longer secrets!

## The Python Exploit 🐍

```python
#!/usr/bin/env python3
"""
OpenSecret Hunter - HTB Challenge Solver
"""
import requests, re
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich import box
from time import sleep

console = Console()

def hunt_and_teach():
    console.print("\n[bold cyan]🔍 Scanning for exposed secrets...[/bold cyan]\n")
    
    with Progress() as progress:
        task = progress.add_task("[yellow]Analyzing client-side code...", total=100)
        
        steps = [
            ("Checking HTML source", 25),
            ("Parsing JavaScript", 25),
            ("Searching for hardcoded secrets", 25),
            ("Extracting vulnerable patterns", 25)
        ]
        
        for step_name, step_value in steps:
            progress.console.print(f"[dim]{step_name}...[/dim]")
            for _ in range(step_value):
                progress.update(task, advance=1)
                sleep(0.01)
        
        r = requests.get("http://94.237.55.124:43313/", timeout=5)
        
        patterns = [r'HTB{.*?}', r'SECRET_KEY\s*=\s*["\'](.*?)["\']']
        findings = []
        
        for pattern in patterns:
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            findings.extend(matches)
        
        progress.update(task, completed=100)
    
    if findings:
        secret = findings[0]
        
        # Security Lesson Panel
        lesson_content = """[bold red]🚨 CRITICAL VULNERABILITY DETECTED 🚨[/bold red]

[bold yellow]Issue:[/bold yellow] [italic]JWT Secret Exposed in Client-Side Code[/italic]

[bold cyan]Security Lessons:[/bold cyan]
• [red]❌[/red] [bold]NEVER[/bold] embed secrets in JavaScript
• [red]❌[/red] Client-side code = [italic]Visible to everyone[/italic]
• [green]✅[/green] Use [bold]environment variables[/bold] instead
• [green]✅[/green] Generate JWTs [bold]server-side only[/bold]
• [green]✅[/green] Store secrets in [bold].env[/bold] files (never commit!)"""

        lesson_panel = Panel.fit(
            lesson_content,
            title="[bold white on red] SECURITY AUDIT REPORT [/bold white on red]",
            border_style="bright_red",
            box=box.HEAVY,
            padding=(1, 3)
        )
        
        console.print(lesson_panel)
        
        # Flag Discovery Panel
        flag_content = f"""[bold green]🎯 VULNERABILITY EXPLOITED SUCCESSFULLY 🎯[/bold green]

[bold cyan]Exposed Secret Found:[/bold cyan]
[blink bold yellow]{secret}[/blink bold yellow]

[bold magenta]The Irony:[/bold magenta]
The flag itself teaches the security lesson!
"[italic]{secret}[/italic]"
→ Open secrets are [bold]NOT[/bold] secrets!

[dim]Attack Vector:[/dim] Source code inspection
[dim]Difficulty:[/dim] Very Easy (but critical!)"""

        flag_panel = Panel.fit(
            flag_content,
            title="[bold cyan on black] 🏴‍☠️ FLAG CAPTURED 🏴‍☠️ [/bold cyan on black]",
            border_style="bright_green",
            box=box.ROUNDED,
            padding=(1, 4)
        )
        
        console.print("\n")
        console.print(flag_panel)
        
        # Quick Commands Panel
        commands_content = """[bold yellow]⚡ QUICK RECONNAISSANCE COMMANDS ⚡[/bold yellow]

[bold cyan]Method 1: Direct Flag Extraction[/bold cyan]
[dim]curl -s URL | grep -o "HTB{.*}"[/dim]

[bold cyan]Method 2: Context Around Secret[/bold cyan]
[dim]curl -s URL | grep -A2 -B2 "SECRET_KEY"[/dim]

[bold cyan]Method 3: Python One-liner[/bold cyan]
[dim]curl -s URL | python3 -c "import re,sys; data=sys.stdin.read(); match=re.search(r'HTB{.*}', data); print(match.group(0) if match else 'Not found')"[/dim]"""

        commands_panel = Panel.fit(
            commands_content,
            title="[bold magenta]🛠️ HACKER'S TOOLKIT 🛠️[/bold magenta]",
            border_style="yellow",
            box=box.SIMPLE_HEAVY,
            padding=(1, 3)
        )
        
        console.print("\n")
        console.print(commands_panel)
        
    else:
        console.print("[red]No exposed secrets found. System appears secure.[/red]")

if __name__ == "__main__":
    console.print("[bold magenta]🚀 Initiating OpenSecret Security Audit Protocol...[/bold magenta]\n")
    hunt_and_teach()
    console.print("\n" + "═" * 60)
    console.print("[bold green on black] ✅ AUDIT COMPLETE - ALWAYS CHECK PAGE SOURCE FIRST! ✅ [/bold green on black]")
    console.print("═" * 60)
```

## Program Output 📥

```
❯ python3 solve.py
🚀 Initiating OpenSecret Security Audit Protocol...


🔍 Scanning for exposed secrets...

Checking HTML source...
Parsing JavaScript...
Searching for hardcoded secrets...
Extracting vulnerable patterns...
Analyzing client-side code... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
┏━━━━━━━━━━━━━━  SECURITY AUDIT REPORT  ━━━━━━━━━━━━━━━┓
┃                                                      ┃
┃   🚨 CRITICAL VULNERABILITY DETECTED 🚨              ┃
┃                                                      ┃
┃   Issue: JWT Secret Exposed in Client-Side Code      ┃
┃                                                      ┃
┃   Security Lessons:                                  ┃
┃   • ❌ NEVER embed secrets in JavaScript             ┃
┃   • ❌ Client-side code = Visible to everyone        ┃
┃   • ✅ Use environment variables instead             ┃
┃   • ✅ Generate JWTs server-side only                ┃
┃   • ✅ Store secrets in .env files (never commit!)   ┃
┃                                                      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


╭─────────────  🏴‍☠️ FLAG CAPTURED 🏴‍☠️  ──────────────╮
│                                                    │
│    🎯 VULNERABILITY EXPLOITED SUCCESSFULLY 🎯      │
│                                                    │
│    Exposed Secret Found:                           │
│    HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}               │
│                                                    │
│    The Irony:                                      │
│    The flag itself teaches the security lesson!    │
│    "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}"             │
│    → Open secrets are NOT secrets!                 │
│                                                    │
│    Attack Vector: Source code inspection           │
│    Difficulty: Very Easy (but critical!)           │
│                                                    │
╰────────────────────────────────────────────────────╯
```

## Why It Works (The Simple Explanation) 🎓

1. **View page source** → Always the first step in web recon
2. **Search for secrets** → Look for keywords like "SECRET_KEY", "password", "token"
3. **Flag in plain sight** → The JWT secret is literally the flag
4. **No exploitation needed** → Just observation and basic web skills

## The 5-Second Solution ⚡

```bash
# Literally one command gets the flag:
curl -s http://94.237.55.124:43313/ | grep -o "HTB{.*}"
# Output: HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}
```

## Key Takeaways 🧠

### What Went Wrong for the Developers:
1. **Client-side JWT generation** - JWTs should NEVER be generated client-side
2. **Hardcoded secrets in JavaScript** - Secrets belong in environment variables
3. **No server-side validation** - Trusting client-generated tokens is dangerous
4. **The flag tells you what's wrong** - The vulnerability is self-documenting!

### Defense Recommendations:
```python
# ❌ NEVER DO THIS (what the challenge did):
const SECRET_KEY = "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}";

# ✅ ALWAYS DO THIS (proper implementation):
# Server-side (Node.js/Express example)
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();  # Load from .env file

const SECRET_KEY = process.env.JWT_SECRET;  # From environment

app.post('/login', (req, res) => {
    const user = authenticate(req.body.username, req.body.password);
    
    // Generate JWT SERVER-SIDE
    const token = jwt.sign(
        { userId: user.id, username: user.username },
        SECRET_KEY,
        { expiresIn: '24h' }
    );
    
    res.json({ token });
});
```

## The Humor Byte 😂

```
Developer: "Let's put the JWT secret in JavaScript!"
Hacker: "Thanks for the free flag!" 🏴‍☠️

JWT in JavaScript = Just Write The secret (in the source code)

Flag: "HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}"
Translation: "Duh!" 🤦‍♂️

The challenge: "Can you find the security flaw?"
The answer: "Yes, it's on line 134... and 135... and..." 📜
```

## Final Flag 🏁
**`HTB{0p3n_s3cr3ts_ar3_n0t_s3cr3ts}`**

## Lessons Learned 📚
1. **ALWAYS check page source first** - Ctrl+U is your best friend
2. **Client-side = Public knowledge** - Anything in the browser is visible to everyone
3. **Secrets belong server-side** - Environment variables exist for a reason
4. **The simplest vulnerabilities are often the most critical** - This was "Very Easy" but teaches a crucial lesson

## Real-World Impact 🌍
This vulnerability, while seemingly simple, is **EXTREMELY COMMON** in real applications. Many developers mistakenly:
- Embed API keys in JavaScript
- Hardcode passwords in frontend code
- Store sensitive configs in client-side bundles
- Trust client-generated security tokens

## Tools Used 🛠️
- `curl` - For quick HTTP requests
- `grep` - For pattern searching
- `rich` - For beautiful terminal output
- `requests` - For Python HTTP client
- `DevTools` - For browser inspection
- `Ctrl+U` - The most powerful hacking tool! 🎯

---

*Remember: If you can see it in your browser, so can everyone else. Client-side secrets are like writing your password on a post-it note stuck to your monitor! 📝💻*

**Happy Hacking!** 🎯🔥