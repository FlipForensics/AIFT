Primary security telemetry and event timeline. Richest artifact for incident reconstruction.
- High-signal Event IDs to prioritize:
  - Logon: 4624 (success), 4625 (failure), 4634 (logoff), 4648 (explicit creds), 4672 (special privileges)
  - Process: 4688 (process creation — command lines are gold)
  - Services: 7045 (new service installed), 4697 (service install via Security log)
  - Accounts: 4720 (created), 4722 (enabled), 4724 (password reset), 4726 (deleted), 4732/4733 (group membership)
  - Anti-forensic: 1102 (audit log cleared)
- Build event chains: logon → process creation → persistence change, with timestamps.
- Flag: unusual logon types (Type 3 network, Type 10 RDP from unexpected sources), process command lines with encoding or download cradles, log gaps suggesting clearing.
- Volume warning: EVTX can have millions of records. Focus on the incident time window and high-signal IDs. Don't enumerate routine system noise.
