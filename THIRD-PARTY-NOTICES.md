# Embedded third-party components

[English](THIRD-PARTY-NOTICES.md) | [Français](THIRD-PARTY-NOTICES.fr.md)

Plume embeds the components below. They are distributed **under their own
license**, not under Plume's AGPL v3. The AGPL v3 applies to the project's own
code; nothing here substitutes it for theirs.

These components are deliberately **embedded** (`web/fonts/`) rather than
fetched at run time: the interface must render without outbound network traffic to a
font CDN, and the content security policy forbids external hosts
anyway. It is also what keeps a third party from observing the analysts' font
requests.

## Inter

- **Location**: `web/fonts/inter-latin.woff2`,
  `web/fonts/inter-latin-ext.woff2`
- **License**: SIL Open Font License 1.1 (`OFL-1.1`)
- **Text**: [`web/fonts/OFL-Inter.txt`](web/fonts/OFL-Inter.txt)
- **Upstream**: <https://github.com/rsms/inter>
- **Version**: 4.001 — the font's `name` table carries
  `Version 4.001;git-66647c0bb`
- **Copyright**: `Copyright (c) 2016 The Inter Project Authors`

## JetBrains Mono

- **Location**: `web/fonts/jetbrains-mono-latin.woff2`,
  `web/fonts/jetbrains-mono-latin-ext.woff2`
- **License**: SIL Open Font License 1.1 (`OFL-1.1`)
- **Text**: [`web/fonts/OFL-JetBrainsMono.txt`](web/fonts/OFL-JetBrainsMono.txt)
- **Upstream**: <https://github.com/JetBrains/JetBrainsMono>
- **Version**: 2.211 — the font's `name` table carries `Version 2.211`
- **Copyright**: `Copyright 2020 The JetBrains Mono Project Authors`

The two copyright notices above are the ones **read from the font itself**
(`name` table, identifier 0), not inferred from the file name. Each license
text was fetched from upstream **as is**: Inter's at commit
`66647c0bb`, which the font declares, JetBrains Mono's at a revision where
it is identical from one version to the next around 2.211.

These files are `latin` / `latin-ext` subsets converted to WOFF2 —
hence **Modified Versions** in the sense of the OFL. That remains allowed: neither Inter
nor JetBrains Mono declares a **Reserved Font Name** after its copyright
notice, so clause 3 does not bite, and clause 5 (stay under the OFL) is
respected since we redistribute them under no other license.

The OFL does not contaminate the rest of the project: its clause 5 states that
the obligation to stay under the OFL does not extend to documents produced with the
font, and its clause 2 explicitly allows redistribution **bundled with
any software** as long as each copy carries the copyright notice and
the license. That is the case here for the source **and for the image**: the `Dockerfile`
copies `web/` in full, so both license files travel with the
fonts they cover.

---

## What is NOT an embedded third party

Read before adding an entry above, so as not to grow the list with
what does not belong in it:

- **Rust dependencies are not vendored.** They are fetched by
  Cargo at build time (`Cargo.lock` pins them, `deny.toml` filters the allowed
  licenses): this repository does not redistribute their code, so it does not have to redistribute
  their license text. That would change if a Cargo `vendor/` were committed.
- **`guatx-core` is a git-dep**, not a copy: `daemon/Cargo.toml` pins it
  by tag. It is under `LGPL-3.0-or-later` and lives in its own repository.
- **The screenshots in `docs/img/` and the SVGs in `web/`** are products of the
  project, not third parties.

## Compliance note

The four `.woff2` files were redistributed **without any OFL text** in the
repository: clause 2 of the OFL 1.1 requires that "each copy contains the above
copyright notice and this license", which was not satisfied. The two
texts were fetched from upstream and added before any publication.

The defect did not show when looking for *missing license files* — it
shows when inventorying what the repository **redistributes**, by content type and not
by extension. The inventory was redone that way: apart from the fonts, the only
tracked binaries are screenshots and SVGs produced by the project, and
no third-party JS/CSS is embedded (no minified bundle, no
`@license` header).

Any update of a font must **bring its license file along at the same
time as the binary**, and update the version stated above — the
version is read from the `name` table, not from the file name.
