# Brand watch

Finds lookalike domains of your own, checks whether they are live and aimed at you, and keeps track of them.

## What to watch

```yaml
brand:
  watch:
    - domain: examplebank.com
      names: [examplebank, "Example Bank"]   # what to look for on pages (default: the domain's first label)
  interval_minutes: 1440                     # 0 = only by hand: zarqa brand run, or Run now on the Brand page
```

Without `brand.watch`, `organization.domains` are watched and `organization.brands` are the names.

## How it works

1. **Generate** up to `max_candidates` (3000) names: omission, repetition, transposition, keyboard
   replacement and insertion, homoglyphs (including `rn` for `m`), vowel swaps, hyphens, bit flips, other
   top-level domains, phishing words (`-login`, `secure`, `support`, ...) and extra dots.
2. **Optionally** add names containing the brand from certificate transparency logs (`ct: true`, public search).
3. **Resolve** each name (A/AAAA; MX with the `dns` extra: `pip install 'zarqa[dns]'`). Names that do not resolve
   are dropped.
4. **Check** each live name, `workers` at a time: the registration date from RDAP (`rdap`, paced to
   `rdap_per_min` because the public service rate-limits) and the page (`page_check`): its title, whether it
   shows a brand name (the domain's own name does not count), whether it asks for a password, whether it is
   parked or for sale, and where it redirects.
5. **Score** 0-100: technique and similarity, mail servers, a recent registration (30 days: +25, 180 days: +10),
   brand shown on a live page (+20), a password asked (+15). A name that redirects to one of your own domains
   is most likely yours and scores 5. Parked pages get no page points.
6. **Track** each finding: first and last seen, the evidence, whether it still resolves, and a status people set
   (new, reviewing, benign, takedown, closed) with a note. New findings are also added to the knowledge store as
   domains tagged `lookalike:<your domain>`.

## What it reveals

Lookups go to this machine's DNS resolver, the RDAP service, the lookalike sites themselves (page check) and,
with `ct`, a public certificate log search. Together they show which names you are checking.

## Tested

On 2026-11-17 against a widely impersonated payment brand, 200 generated names: 132 resolved; the top finding was
a `support...` name registered 61 days earlier whose page asks for a password; parked "for sale" pages no longer
counted as brand use after a fix found in this run. The run took about 5 minutes, mostly RDAP pacing. Many old
names registered on the same date were probably the brand's own defensive registrations; Zarqa does not yet
compare registrants, so they appear with middling scores.
