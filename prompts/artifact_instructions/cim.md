WMI event subscription persistence — a stealthy and often overlooked persistence mechanism.
- Focus on the three components: EventFilter (trigger), EventConsumer (action), and FilterToConsumerBinding (link between them).
- Suspicious: CommandLineEventConsumer or ActiveScriptEventConsumer invoking powershell, cmd, wscript, mshta, or referencing external script files. Any consumer executing from user-writable paths.
- High-risk triggers: logon, startup, or timer-based EventFilters that re-execute payloads automatically.
- This artifact is rarely used legitimately outside enterprise management tools (SCCM, monitoring agents). Any unexpected subscription is worth flagging.
- Cross-check: execution of the consumer's target command should appear in EVTX process creation, prefetch, or shimcache.
