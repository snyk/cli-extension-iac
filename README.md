<p align="center">
  <img src="https://snyk.io/style/asset/logo/snyk-print.svg" />
</p>

# Snyk IaC Test CLI Extension

## Overview

This module implements the Snyk CLI Extension for IaC workflows.

## Workflows

- `snyk iac test`

### Excluding files and directories

You can exclude files or directories from IaC scans using the `--exclude` flag. The value is a comma-separated list of paths relative to the input directory. Both of the following are supported:

```bash
snyk iac test --exclude=dir-to-skip,subdir/file.tf
snyk iac test --exclude "dir-to-skip,subdir/file.tf"
```

The exclusion is applied in addition to existing ignore mechanisms (such as `.gitignore` and `.snyk`).
