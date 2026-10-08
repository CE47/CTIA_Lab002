/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../new.scenario (beginner-new-admin-account-001)
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-new-admin-account-001',
    title: 'The Phantom Administrator',
    difficulty: 'Beginner',
    seed: 104,
    caseRef: 'CASE 002',
    host: 'sec-win-05',
    host_ip: '10.0.4.12',
    log_sources: ['auth'],

    mission: {
      brief: 'Investigate workstation sec-win-05.',
      objective: 'Determine whether someone created a persistent privileged account on this workstation.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      "An attacker who compromised a standard user account on a workstation created a new local administrator " +
      "account called 'HelpDeskSupport', added it to the Administrators group, and then authenticated as that " +
      "account. This is a common persistence technique: the attacker survives even if the original compromised " +
      "account is disabled.",

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4624-kpatel',
        ts: '08:01:12',
        code: 4624,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'kpatel',
        text: 'Successful interactive logon. Source 203.0.113.45 (remote). Logon type 10.',
        tags: 'context',
        why:
          'This is the foothold — the interactive entry point, not the malicious behavior itself. You need it to ' +
          'anchor the timeline, but a single remote logon is not evidence of persistence.'
      },
      {
        id: 'ev-4720-acct',
        ts: '08:04:22',
        code: 4720,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'kpatel',
        text: "Local account created: 'HelpDeskSupport'. Triggered by: kpatel.",
        tags: 'signal',
        why:
          'Creating a brand-new local account is the persistence action. The attacker plants an alternate identity ' +
          'so that disabling the original account no longer removes their access.'
      },
      {
        id: 'ev-4732-group',
        ts: '08:05:01',
        code: 4732,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'kpatel',
        text: "'HelpDeskSupport' added to security group 'Administrators'. Triggered by: kpatel.",
        tags: 'signal',
        why:
          'Less than a minute after creation the account is given administrator rights. The escape hatch that looked ' +
          'like routine support is now a privileged one.'
      },
      {
        id: 'ev-4624-hds',
        ts: '08:08:12',
        code: 4624,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'HelpDeskSupport',
        text: 'Successful interactive logon. Source 203.0.113.45 (remote). Logon type 10.',
        tags: 'signal',
        why:
          'The account has existed for four minutes and is already being used — from the same external source that ' +
          'opened the foothold session. A new identity, used fast, from a known-attacker source.'
      },
      {
        id: 'ev-4672-hds',
        ts: '08:11:24',
        code: 4672,
        kind: 'event',
        host: 'sec-win-05',
        actor: 'HelpDeskSupport',
        text: 'Special privileges assigned to new logon.',
        tags: 'signal',
        why:
          'A high-integrity logon for a user that did not exist an hour ago. This confirms the account is exercising ' +
          'its new administrator rights — the final step of the lifecycle.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:41', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:03', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:11', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:18', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:06:33', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:07:44', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'rneuman', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:09:12', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:10:26', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:12:03', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:13:47', code: 4672, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:15:50', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:17:09', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:19:28', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:21:46', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:24:03', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:26:12', code: 4634, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:29:34', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:33:20', code: 4672, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:36:02', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:38:17', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-4720',
        ref: 'ALERT-01',
        severity: 'medium',
        title: 'New user account created',
        blurb: "A new local account 'HelpDeskSupport' was created on sec-win-05 (Event 4720) by user 'kpatel'.",
        detail:
          'Security Event 4720 — "A user account was created". Fields of interest: TargetUserName (the new ' +
          'account), SubjectUserName (who created it), and the timestamp. Creating a local account is normal only ' +
          'when there is a provisioning workflow behind it.',
        hint: 'Ask: who created it, when, and does a new local account fit any known onboarding?'
      },
      {
        id: 'al-4732',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Account added to privileged group',
        blurb: "The newly created account 'HelpDeskSupport' was added to the local Administrators group on sec-win-05 (Event 4732).",
        detail:
          'Security Event 4732 — "A member was added to a security-enabled local group". A brand-new account joining ' +
          'Administrators within a minute of its creation is the escalation step. Group membership is what turns an ' +
          'identity into a privileged one.',
        hint: 'Ask: did the account already have a role that justifies administrator rights?'
      },
      {
        id: 'al-4624',
        ref: 'ALERT-03',
        severity: 'high',
        title: 'First logon by newly created account',
        blurb: "The account 'HelpDeskSupport' successfully authenticated to sec-win-05 minutes after being created (Event 4624).",
        detail:
          'Security Event 4624 — "An account was successfully logged on". The logon comes from 203.0.113.45, the ' +
          'same external source used to open the original foothold session minutes earlier.',
        hint: 'Ask: how old is the account at first use — and does the source match anything you have already seen?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account information — kpatel',
        blurb: 'Directory record for the account that created the new local account.',
        detail:
          'kpatel — K. Patel, Marketing Coordinator. Group membership: Domain Users only. NOT a member of the ' +
          'local Administrators group, and has no documented role that creates local accounts. Last password ' +
          'change 39 days ago.',
        hint: 'Ask: does this account have any legitimate reason to create local administrators?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — other hosts this hour',
        blurb: 'Reference traffic for the estate during the same window.',
        detail:
          'In this hour, 5 baseline users generated 20 logon/logoff/privilege events across FIN-WS-14, HR-LT-03, ' +
          'ENG-WS-02, OPS-WS-09 and FIN-LT-11. None created a local account. None added an account to ' +
          'Administrators. No other host has a HelpDeskSupport account.',
        hint: 'Ask: is account creation unique to sec-win-05, or is it something the estate does routinely?'
      }
    ],

    alerts: [
      { name: 'New user account created', severity: 'medium' },
      { name: 'Account added to privileged group', severity: 'high' },
      { name: 'First logon by newly created account', severity: 'high' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:01:12', label: 'Logon', detail: "1 successful logon for 'kpatel' on sec-win-05 from 203.0.113.45 (compromised session)", net: null },
      { t: 'T+3', ts: '08:04:22', label: 'Account', detail: "user_account_created (4720): account 'HelpDeskSupport' created on sec-win-05 by 'kpatel'", net: null },
      { t: 'T+4', ts: '08:05:01', label: 'Group', detail: "group_membership_added (4732): 'HelpDeskSupport' added to Administrators on sec-win-05 by 'kpatel'", net: null },
      { t: 'T+7', ts: '08:08:12', label: 'Logon', detail: "1 successful logon for 'HelpDeskSupport' on sec-win-05 from 203.0.113.45", net: null },
      { t: 'T+10', ts: '08:11:24', label: 'Privilege', detail: "special_privileges_assigned (4672) for 'HelpDeskSupport' on sec-win-05", net: null }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'Random administrative activity by several users' },
        { id: 'b', label: 'A legitimate onboarding: a new staff member created and granted access' },
        { id: 'c', label: 'A foothold session used to create a new account, elevate it to Administrators, and authenticate as it — inside ten minutes' },
        { id: 'd', label: 'Multiple failed logons followed by an account lockout' }
      ],
      correct: ['c'],
      xp: 10,
      explain:
        'The account did not exist before 08:04, was granted Administrator rights within a minute of creation, and ' +
        'was then logged into from the same external source that opened the foothold session. The compression — ' +
        'create, elevate, use in ten minutes — is what rules out routine onboarding.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-src', label: '203.0.113.45', sub: 'external source', x: 8, y: 8 },
      { id: 'n-kpatel', label: 'kpatel', sub: 'compromised account', x: 8, y: 60 },
      { id: 'n-host', label: 'sec-win-05', sub: 'host', x: 40, y: 40 },
      { id: 'n-acct', label: 'HelpDeskSupport', sub: 'new local account', x: 72, y: 8 },
      { id: 'n-group', label: 'Administrators', sub: 'privileged group', x: 72, y: 60 },
      { id: 'n-log', label: '4624 / 4672', sub: 'privileged logon', x: 40, y: 80 }
    ],
    boardLinks: [
      { from: 'n-src', to: 'n-kpatel', label: 'authenticates as', correct: true },
      { from: 'n-kpatel', to: 'n-acct', label: 'created', correct: true },
      { from: 'n-acct', to: 'n-group', label: 'added to', correct: true },
      { from: 'n-acct', to: 'n-log', label: 'log on as', correct: true },
      { from: 'n-host', to: 'n-acct', label: 'hosts', correct: true },
      { from: 'n-src', to: 'n-host', label: 'patches', correct: false },
      { from: 'n-group', to: 'n-kpatel', label: 'created by', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify creating a new local administrator account?',
        options: [
          { id: 'a', label: 'Persistence — an alternate identity the attacker can keep using after the original access is lost' },
          { id: 'b', label: 'Reconnaissance — gathering information about the host' },
          { id: 'c', label: 'Impact — destructive action against data' },
          { id: 'd', label: 'Privilege Escalation only — no persistence value on its own' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'A new account that survives the original compromise is a persistence mechanism. Granting it administrator ' +
          'rights makes the escape hatch privileged — escalation builds on top of the persistence, it does not ' +
          'replace it.'
      },
      {
        id: 'q-ps',
        prompt: 'Why would an attacker add the new account to the Administrators group?',
        options: [
          { id: 'a', label: 'To match the corporate naming convention for help desk accounts' },
          { id: 'b', label: 'To obtain persistent privileged access under a plausible, support-sounding name' },
          { id: 'c', label: 'Windows requires new accounts to be administrators before they can be used' },
          { id: 'd', label: 'To prevent the account from appearing in the security logs' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          "'HelpDeskSupport' reads as legitimate support tooling, which buys time. Administrator rights make it a " +
          'privileged command channel rather than an unprivileged login. Plausible name plus high privilege plus ' +
          'creation by a compromised account is the persistence–escalation pattern.'
      }
    ],

    decodedCommand: {
      encoded: 'kpatel 08:04:22 → HelpDeskSupport → Administrators → logon 08:08:12',
      decoded: 'created (4720) → added to Administrators (4732) → successful logon (4624) with special privileges (4672)',
      note:
        'The three event IDs read as one action: create the account, grant it Administrator rights, then log in ' +
        'as it. That lifecycle — not the name, not any single event — is the persistence technique.'
    },

    attack: {
      prompt: 'Which technique best explains this activity?',
      primary: {
        options: [
          { id: 'a', label: 'Create Account: Local Account', meta: 'T1136.001 · Persistence' },
          { id: 'b', label: 'Scheduled Task/Job', meta: 'T1053.005 · Persistence' },
          { id: 'c', label: 'OS Credential Dumping', meta: 'T1003 · Credential Access' },
          { id: 'd', label: 'Data Destruction', meta: 'T1485 · Impact' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The defining artifact is a brand-new local account created by a compromised user, then made an ' +
          'administrator. That is account creation as persistence: even if the original foothold is discovered ' +
          'and disabled, the attacker still holds a valid identity on the host. The account is the mechanism, ' +
          'not a side effect.'
      },
      alsoPresent: {
        prompt: 'Two other techniques are genuinely present in this activity. Select both.',
        options: [
          { id: 'a', label: 'Account Manipulation', meta: 'T1098 · Privilege Escalation' },
          { id: 'b', label: 'Valid Accounts: Local Accounts', meta: 'T1078.002 · Defense Evasion / Persistence' },
          { id: 'c', label: 'System Owner/User Discovery', meta: 'T1033 · Discovery' },
          { id: 'd', label: 'Indicator Removal', meta: 'T1070 · Defense Evasion' }
        ],
        correct: ['a', 'b'],
        xp: 10,
        explain:
          'Adding the account to the Administrators group is Account Manipulation (T1098) — permission ' +
          'modification that escalates access. Logging in as that newly-created local user is Valid Accounts: ' +
          'Local Accounts (T1078.002). Creation was the persistence; the grant and the logon are what make it ' +
          'usable and privileged.'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: 'HelpDeskSupport', role: 'indicator' },
        { id: 'i2', label: '203.0.113.45', role: 'indicator' },
        { id: 'i3', label: 'sec-win-05', role: 'context' },
        { id: 'i4', label: 'kpatel', role: 'context' },
        { id: 'i5', label: 'Administrators', role: 'behaviour' },
        { id: 'i6', label: 'Event 4732', role: 'context' },
        { id: 'i7', label: 'ten-minute lifecycle', role: 'behaviour' },
        { id: 'i8', label: 'local account creation', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'Two of these eight items are things you would act on directly: the account name HelpDeskSupport (disable ' +
        'and hunt for it) and the external source 203.0.113.45 (block it). The behaviours — local account ' +
        'creation and the rapid privilege grant — are worth detections of their own: new accounts joining ' +
        'Administrators. sec-win-05, kpatel and Event 4732 are context: they scope the incident and drive pivots, ' +
        'but they are not indicators of compromise.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host is compromised?',
        options: [
          { id: 'a', label: 'sec-win-05' },
          { id: 'b', label: 'FIN-LT-11' },
          { id: 'c', label: 'HR-LT-03' },
          { id: 'd', label: '10.0.4.20' }
        ],
        correct: ['a'],
        xp: 10
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: "An attacker pivoted from a compromised account to a new local administrator account ('HelpDeskSupport') to keep privileged access if the original account was disabled." },
          { id: 'b', label: 'A new help desk member was onboarded with the standard administrator provisioning process.' },
          { id: 'c', label: 'A failed login caused the system to create a recovery account.' },
          { id: 'd', label: 'The workstation ran routine maintenance that briefly elevated a service account.' }
        ],
        correct: ['a'],
        xp: 10
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'The account was created by a non-administrative user (kpatel)' },
          { id: 'b', label: 'It was added to the Administrators group within a minute of creation' },
          { id: 'c', label: 'It was logged into from the same external source as the original compromise' },
          { id: 'd', label: 'It is a brand-new account with no legitimate business role in the directory' },
          { id: 'e', label: 'Local accounts are always malicious' },
          { id: 'f', label: 'The host needed extra administrators for an ongoing project' }
        ],
        correct: ['a', 'b', 'c', 'd'],
        xp: 10
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Disable and preserve the HelpDeskSupport account for forensic review' },
          { id: 'b', label: 'Reset the kpatel credentials and revoke active sessions' },
          { id: 'c', label: 'Hunt the estate for other locally-created administrator accounts' },
          { id: 'd', label: 'Extend the maintenance window for all workstations in finance as a precaution' },
          { id: 'e', label: 'Disable local account creation across the whole estate permanently' },
          { id: 'f', label: 'Reimage the directory server as a precaution' }
        ],
        correct: ['a', 'b', 'c'],
        xp: 10
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: "Local account 'HelpDeskSupport' created on sec-win-05 (4720)", key: true },
        { id: 'r2', label: "'HelpDeskSupport' added to Administrators by kpatel (4732)", key: true },
        { id: 'r3', label: "Successful logon by 'HelpDeskSupport' from 203.0.113.45 (4624) followed by special privileges (4672)", key: true },
        { id: 'r4', label: 'Baseline users logged in and out on other hosts during the same hour', key: false },
        { id: 'r5', label: 'Windows logs every account creation, so the event is routine', key: false },
        { id: 'r6', label: 'Five baseline users were active on the estate', key: false },
        { id: 'r7', label: 'The account name matches the help desk naming convention', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'No single record is damning on its own. A new account could be onboarding; a group addition could be ' +
        'admin fixing access. What makes this defensible is the three-step lifecycle: created by a non-admin ' +
        'session, elevated to Administrators, and used from the same external source. Three artifacts that only ' +
        'make sense together.'
    },

    ground_truth: {
      new_accounts_created: 1,
      new_account_name: 'HelpDeskSupport',
      privileged_group_additions: 1,
      successful_logons_for_helpdesksupport: 1,
      special_privilege_events_for_new_account: 1,
      target_host: 'sec-win-05',
      event_ids_present: [4624, 4672, 4720, 4732]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the behavior and explained it. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Start with Event 4720 and work outward from there.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Look at where the second logon comes from — and how old the account is at that moment.' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'One event creates an identity, one gives it power, and one uses it. Which three event IDs are they?' },
      explain: { label: 'Explain', mult: 0.5, text: 'kpatel, a non-administrative account, created HelpDeskSupport (4720), added it to Administrators (4732), then logged in as it from the same external source (4624) with special privileges (4672). That lifecycle is Create Account: Local Account, T1136.001 — persistence — with Account Manipulation (T1098) and Valid Accounts: Local Accounts (T1078.002) alongside.' }
    }
  });
})();