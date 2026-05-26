# Specifica Protocol Skill

**Purpose:** Operate consistently within projects organized using the [Specifica](https://specifica.org) convention — an open standard for AI-readable project knowledge as plain markdown.

## When to activate

- A project contains a `.specifica/` folder in its knowledge, **or**
- Project custom instructions explicitly invoke this skill.

---

## 1. File structure

```
.specifica/
├── principles.md          ← project-wide cross-cutting standards (one file)
├── mvp/                   ← active version folder (or 0.1, 1.2, …)
│   ├── spec.md
│   ├── design.md
│   └── tasks.md
└── 0.0.1/                 ← past version folders (frozen historical record)
    └── …
```

One `principles.md` at the root. One folder per version, named after its tag (`mvp`, `0.1`, `1.2`, semver-style). Each version folder contains exactly three files.

**Current version:** the highest version tag by semver ordering (`mvp` is lowest). All older folders are frozen.

---

## 2. File semantics

| File | Holds | Doesn't hold |
|---|---|---|
| `principles.md` | Cross-cutting rules: naming discipline, retired terms, comms style, "always/never" doctrine | Anything version-specific |
| `spec.md` | **What** this version is — outcomes, scope, constraints, acceptance criteria | Implementation detail |
| `design.md` | **How** it's organized — structure, decisions, components, guardrails | Open work items |
| `tasks.md` | **Open work** — discrete items, status, owners, dates | Long narrative |

---

## 3. Read protocol

Before answering any substantive question, consult Specifica files in this order:

1. `principles.md` — any rule, convention, or "always/never" question.
2. Current version `spec.md` — scope, intent, outcomes.
3. Current version `design.md` — how things are organized.
4. Current version `tasks.md` — status, open work, completed work.

If the question references a past version, read that version's folder. Do not blend versions silently — name them when context spans versions.

---

## 4. Write protocol — propose-diff

Claude does **not** edit Specifica files inline during a session. Instead:

- Hold proposed changes in working memory during the session.
- When the user requests an update ("status update", "wrap this up") or at natural session end, output a **proposed diff** covering:
  - `tasks.md` — items completed, items added, status changes, reorderings.
  - `spec.md` — scope adjustments, new constraints (rare).
  - `design.md` — structural or architectural updates.
  - `principles.md` — only when a new cross-cutting rule has clearly been established.
- The user accepts, rejects, or edits each diff before any file is updated.

---

## 5. Scaffolding a new project

If no `.specifica/` folder exists and the user invokes the skill:

1. Ask for the initial version tag (`mvp` is a reasonable default).
2. Create `.specifica/principles.md` (empty, ready to populate).
3. Create `.specifica/<version>/spec.md`, `design.md`, `tasks.md` (empty or templated).
4. Offer to populate `spec.md` from a brief description of the project's purpose.

The skill document itself stays in the project's knowledge root, not inside `.specifica/`. The skill is the *protocol*; `.specifica/` is the *content*.

---

## 6. Version transitions

When the user signals a version cut (e.g., "let's cut 0.1"):

1. Freeze the current version folder. Closed tasks stay as historical record.
2. Create a new version folder named after the new tag.
3. Copy `spec.md` and `design.md` forward as starting points; propose diffs to reflect the new version's intent.
4. Open (incomplete) tasks roll forward into the new `tasks.md`. Closed tasks stay behind.
5. `principles.md` is unchanged — it's cross-cutting, not version-bound.

---

## 7. Operating rules

- Cite `principles.md` directly; don't paraphrase.
- If a user request conflicts with a `principles.md` rule, surface the conflict before acting.
- Status questions → lead with `tasks.md`, cite `design.md` for context.
- "How does this work" questions → lead with `design.md`, cite `spec.md` for intent.
- Non-Specifica files in project knowledge are supplementary, not authoritative.

---

## Activation line for project custom instructions

Add the following line to the new project's custom instructions:

> *This project follows the Specifica protocol. Read `specifica-skill.md` in project knowledge before responding. Treat `.specifica/principles.md` as authoritative for cross-cutting rules.*
