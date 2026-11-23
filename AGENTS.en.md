# Rules for any agent or contributor working on this repository

[Français](AGENTS.md) | [English](AGENTS.en.md)

This repository is **public**. This file exists because the rules below have already been
broken, and the memory of a session survives neither a change of agent nor a loss of
context. What follows is therefore **enforced by guards**, not merely written down.

## 1. Identity — `guatxlabs <noreply@guatx.com>`, no exceptions

The **global** git configuration of a workstation may hold something else; every fresh clone
inherits it. Set the identity **locally**, in every clone:

```sh
git config user.name  "guatxlabs"
git config user.email "noreply@guatx.com"
git config core.hooksPath .githooks     # arms the guards
```

`.githooks/pre-commit` refuses a commit whose author is not that one.

**NO `Co-Authored-By` TRAILER.** GitHub does not build the Contributors page from the author
alone: it also counts these trailers on the default branch, and it matches by
ADDRESS. A single trailer is enough to list one more account as a contributor to the
project. This repository shows only one identity, the one that takes responsibility for the code.
The verifier refuses the trailer, and it reads the message FILE, not the cleaned body —
that body already strips these lines, so a guard that read it could never find anything
and would pass green while blind.

## 2. Write for the reader of the code — never for a person

A commit message says **what changes and why**. It does not narrate how the work
went. The following are **refused** by `.githooks/commit-msg` and by CI:

| Family | Refused example |
|---|---|
| first-person narrative | « j'ai corrigé » (“I fixed”), « je pensais que » (“I thought that”) |
| possessive pointing at the author | « ma faute » (“my fault”), « mon correctif » (“my fix”), « mes deux verdicts » (“my two verdicts”) |
| session marker | « hier » (“yesterday”), « à ce jour » (“as of today”) in the temporal sense, « 4e fois de la session » (“4th time this session”) |
| addressed to a person, or quoting an exchange | « demandé par X » (“requested by X”), « X m'a dit » (“X told me”) |
| machine path | `/home/<compte>` |
| personal account, address outside `@guatx.com` | — |

**What has value and must stay**: the measurement (a figure **with its date**), what was
**refuted**, and the **reason** for a design choice. The work log — who tried what, in
which order, in how many attempts — belongs in an internal repository.

The same rule applies to **documentation** and **code comments**: they address the
reader, not an interlocutor.

## 3. How the rule is held

```
.github/scripts/verifier-message-de-commit.sh   la règle, écrite UNE fois
.githooks/commit-msg                            boucle de retour locale (contournable)
.github/workflows/message-public.yml            application qui LIE, sur la plage poussée
```

The hook **delegates** to the CI script: a rule written twice ends up diverging. The
hook can be bypassed (`--no-verify`) and is lost with every clone; CI cannot. To check a
message before committing:

```sh
git log -1 --format=%B > /tmp/m && ./.github/scripts/verifier-message-de-commit.sh /tmp/m
```

The rule is the same on both sides; **the text, not quite**, and the hook says so. Measured on
2026-08-26: git has not yet cleaned the file when it calls the hook, and it will clean it
**only if the message was edited** — `git commit -m` keeps a comment line
in the published message, and the file is named `COMMIT_EDITMSG` in both cases. The hook
therefore applies git's cleanup itself (`git stripspace --strip-comments`, which follows
`core.commentChar`) and **warns** when that cleanup changes the verdict, quoting what CI
will refuse. CI, for its part, cleans nothing: it judges the message **as published**.

CI judges **every pushed commit, on every branch**, message and identity, over a range derived
**once**. When the starting point of the push is unreachable — branch creation,
force push, manual trigger — it judges the **superset** of what was
pushed, that is, all reachable history: a superset can only refuse more,
never acquit less. It never passes green on what it could not read — `2` means
“nothing was read”, distinct from `1`, which means “refused”.

### A pull request is not a way in

Measured on 2026-08-26 on this repository's settings and on a **real** squash merge
configured identically: **the merge button cannot produce any commit admissible here.**
Three refusals add up, and no setting removes them:

| What the platform adds to the squash commit | What refuses it |
|---|---|
| the sign-offs of the squashed commits, **carried over** — hence the foreign address they bear | address outside `@guatx.com` |
| one `Co-authored-by:` line per distinct author | co-signature trailer |
| a committer that is **the platform's account**, not the canonical identity | non-canonical identity |

Proven by mutation: the same body, stripped of only these lines, passes.

**Consequence, and it is lasting.** The only way into the published history is a
**direct push** to the publication branch, under the canonical identity. A contribution,
or a dependency update, is **taken over locally**, replayed under that identity, and
pushed; the message cites the request number, so the discussion stays findable.
The dependency bot keeps all its value for the **alert** — it says which version moves and
why — and none for the merge.

**These requests therefore stay red, and that red is TRUE.** It is not fixed branch by
branch: nobody can rewrite the message of a commit a bot has just made. It
must not be switched off either — a guard that stopped judging these commits would not remove
the cause, it would only remove the ability to see it, and the publication branch would
lose its only redundancy: every commit would land there without ever having been read.

## 4. What is not published

This repository is public, and two categories of content have no place in it. No
mechanical guard catches them: they rest on review, which is why they are
written here.

**OPERATIONAL FIGURES FROM A REAL DEPLOYMENT.** Database size, number of events,
observed disk or memory usage, duration measured on a given machine, measurement date,
host name, IP address, container or namespace name. A design figure is published
(the 2 GiB memory budget is a project constraint); a figure read off an
installation is not. It tells an attacker about a target and teaches nothing to
a reader of the code.

**THE WORK LOG.** docs/ROADMAP.md, in this repository, is a PUBLIC INDEX: one row
per key, its state, what a reader needs to know, and the known limits named
plainly. It is not a campaign log. The detailed log — refuted hypotheses,
operational measurements, how the work went — lives on the internal repository, branch
journal-interne-avant-sommaire, and is never pushed here.

WHY THE INDEX SURVIVES WHILE THE LOG GOES: the commit messages of this repository
CITE roadmap keys. A cited key whose entry the public index lacked
would be a reference into the void. The test daemon/src/tests/cles_de_roadmap_uniques.rs reads
this file and refuses a duplicate key; it assumes Markdown table lines
starting with a vertical bar. Changing the shape of the document breaks this guard.

## 5. What the guard does not do

It only judges **objective** families. It cannot decide whether a sentence
“addresses the public”: a guard that claimed to do so would produce noise and
end up disarmed. That part rests on review — and the rule written above is what
makes it possible.

## 6. The working tree is never yours alone

Several pieces of work cross in this repository, and many are not committed yet. Two
ordinary operations destroy them, and both were measured here on 2026-08-28.

**Never undo a mutation with `git checkout --` or `git restore`.** Testing a guard by
mutating a file and then putting it back is the right method; putting it back with `checkout` returns it to
the index, that is, to `HEAD`, and takes away everything that had not been added to it. A file never
indexed leaves no recoverable object — `git fsck --dangling` returns nothing, and the loss is
permanent. Save the content before the mutation, outside the repository, and restore from that copy;
or better, mutate in a mirror and do not touch the shared tree.

**A mirror is made with `git archive HEAD | tar -x`, never with a recursive copy.** The temporary
directory is often mounted in RAM: a copy that drags along the build directory puts
several gibibytes there, and at saturation *every* command fails — with no message saying so, which
gives the impression of a broken desktop. `git archive` takes only tracked files, which is
precisely the corpus a guard needs. Delete your mirrors when you are done.

**Corollary for guards with a tracked corpus.** A guard whose corpus comes from `git ls-files` is
blind to a new file until it is added. Its green is then an artifact: run
`git add -N` on your new files *before* playing the battery, otherwise you validate a tree that
integration will not see the way you do.

## 7. The machine is never yours alone either

**Play the battery with `.github/scripts/jouer-la-batterie-de-gardes.sh`, never with a loop of
your own.** The launcher asks a question before taking the machine — is a cargo build or a
test suite in progress? — and REFUSES, saying what it is waiting for, with `--attendre` to
wait instead. It then plays the guards **in series**, one at a time, and asks the question again
before each one.

This is not a style preference, it is `P8.27-h`: some forty scripts launched at the same
time starve the witnesses that measure a memory peak, and those witnesses then REFUSE TO
CONCLUDE — a perfectly unreadable red for whoever just caused it. The rule “nothing heavy
during a suite” was written out in full the day before the last occurrence: writing a
rule does not enforce it.

Its exit codes separate what reading conflates: `1` a violated property, `2` a guard
that measured **nothing** (invalid instrument, missing interpreter), `3` nothing measured at all because
the machine was busy **or could not be consulted**. An instrument refusal is not a
violated property. **The criterion is the exit code each guard declares**, never the text of
its log: sixteen guards use the phrase « REFUSE DE CONCLURE » (“refuses to conclude”), and at least one writes it
in its ACCUSATION message — using it to classify laundered a violated property into
“nothing measured”. When the code accuses and the text refuses, the launcher counts RED and **names the
contradiction** instead of settling it silently.

**What the probe sees, and what it does not.** It looks at the artifact directories of the
**four** crates (derived from their `Cargo.toml`, not from a list), it canonicalizes every path
before comparing it with `/proc`, and it excludes **stopped** processes — which consume nothing.
It does NOT see the processes of another user (measured on this desktop: 302 of the 433
executables are unreadable), nor those of another PID namespace; its verdict therefore says “that I
can see”, not “none”.

**A heavy tool of this repository takes the token** (`sonde_jeton_prendre`): that is what makes the
battery visible to `compter-les-tests.sh` and forbids two batteries at once. Two separate
clones have two separate tokens.

From a `git commit`, the hook can receive **no** argument: to wait instead of
refusing, use `COMPTER_ATTENDRE=1 git commit …`; to skip the check entirely, `--no-verify`.

The launcher is wired into **no** integration workflow, and must not be: there each
guard is a named step, which is better, and the work is isolated.

**It is still not a boundary**, and `--forcer` exists. A written rule does not enforce itself;
a mechanism you go through by default does.
