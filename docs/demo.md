# Demo

```bash
zarqa demo --run                 # builds ~/.zarqa-demo and runs a sample investigation
ZARQA_HOME=~/.zarqa-demo zarqa serve      # http://127.0.0.1:8631
```

or with Docker: `docker compose --profile demo up demo` (kept in memory, gone when stopped).

What it does, all offline (no model, no feeds, no lookups):

- writes a home folder with a fictional organization profile (an energy utility using a VPN appliance) and one
  intelligence requirement;
- adds three fictional sample reports (a campaign write-up, an advisory, and an unrelated news roundup), with
  documentation-range IP addresses (RFC 5737) and `.example` domains;
- extracts them with the rules and a **scripted stand-in for the model**: it answers from fixed rules about the
  sample data, labels every reply "[scripted demo, not AI]", and its output goes through the same quote checks as
  a real model's;
- scores relevance (the advisory naming the organization's VPN appliance ranks first, the news roundup scores 0);
- adds three fictional lookalike-domain findings to the brand watch;
- with `--run`, investigates "What do we know about 203.0.113.45?" and prints the cited answer.

The UI shows a banner saying the data is fictional and the model is a script. To see real extraction, point
the `extractor` and `analyst` roles at a model (Settings) and add a real report.
