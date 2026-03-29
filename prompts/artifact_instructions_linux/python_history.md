Python interactive REPL history — records commands typed in the Python interpreter.
- Suspicious: import os/subprocess/socket/pty, eval/exec calls, network connections (socket.connect, urllib, requests), file operations on sensitive paths (/etc/shadow, /root/.ssh), os.system or subprocess.call with shell commands, pty.spawn for shell upgrades.
- Often used for interactive exploitation after initial access — attacker drops into Python to avoid bash history or leverage Python capabilities.
- Stored in ~/.python_history by default. No timestamps.
- Cross-check: Python interpreter execution should appear in bash_history (python/python3 commands) or process logs.
