# Bitbucket adapter

The shipguard image is the pipe. Its default command, `shipguard run`, scans, gates and posts a Code Insights report. There is no adapter code: `pipe.yml` is listing metadata; consumers use `pipe: docker://ghcr.io/faridlamaul/shipguard:vX.Y.Z`.

```yaml
- pipe: docker://ghcr.io/faridlamaul/shipguard:vX.Y.Z
  variables:
    SCANNERS: all          # or a comma list of secrets, sast, sca, iac
    MODE: enforce          # or audit; empty uses .shipguard.yaml
    CONFIG: .shipguard.yaml
    CODE_INSIGHTS: "true"  # "false" skips the report
```

- **Schedules.** Bitbucket has no variable for scheduled runs. A scheduled custom pipeline sets `SHIPGUARD_EVENT: schedule` as a pipe variable.
- **History (V2).** PR and schedule runs need the full history. shipguard runs `git fetch --unshallow` itself, through the Pipelines proxy, so `clone: depth: full` is not needed. Verified on Bitbucket Cloud (docs/verification.md, V2).
- **Code Insights proxy (V3).** A pipe runs in its own container, so shipguard posts through `http://host.docker.internal:29418` when `BITBUCKET_PIPE_STORAGE_DIR` is set, and through `http://localhost:29418` when the image runs as a step image. `SHIPGUARD_BITBUCKET_PROXY` overrides it. No token is needed (V3).

`test/bitbucket-pipelines.yml` is the pipeline used to test the pipe in the Bitbucket test repository. Full usage: [docs/bitbucket.md](../../docs/bitbucket.md).
