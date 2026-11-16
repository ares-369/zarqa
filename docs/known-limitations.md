# Known limitations

- Only the foundation exists. Zarqa does not collect, extract or analyse intel yet (see the
  [roadmap](roadmap.md)).
- Jobs run on the server's own threads only (`jobs.mode: local`); separate worker processes are not
  supported yet.
- The privacy layer is pattern-based and can miss values, for example a name in free text. List
  anything that must never leave under `privacy.terms` or `privacy.patterns`.
