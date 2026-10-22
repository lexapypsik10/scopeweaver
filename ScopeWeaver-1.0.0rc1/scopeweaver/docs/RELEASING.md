# Release checklist

The delivered version is **1.0.0rc1**, not a claim of a published stable GitHub release.
The project name and any eventual package/repository name have not been reserved.

Before promotion to v1.0.0:

- Run `ruff check .`, `ruff format --check .`, `mypy src` and the complete pytest coverage gate.
- Build an sdist and wheel; install the wheel in a clean environment and exercise CLI/lab/report.
- Obtain successful GitHub Actions runs on the configured Ubuntu/Windows Python matrix.
- Exercise representative permitted labs on Kali Linux and supported Debian/Ubuntu versions.
- Review the scope boundary, dependency versions and release artifacts.
- Configure the real repository's private vulnerability reporting channel.
- Review the documentation's limitations, changelog and version identifiers together.
- Update `pyproject.toml` and `src/scopeweaver/__init__.py`, rerun checks, and create an annotated tag.
- Publish the reviewed distributions and checksums in a manually created GitHub Release.

There is no automated deployment, package upload or release token in this repository.
CI has read-only repository permissions and uploads build/coverage artifacts only.

## Publishing a new repository

The archive contains no GitHub credential or remote URL. After reviewing it, create a new
empty repository in your own account, select the intended visibility, and run these commands
from the project directory (replace `YOUR_REPOSITORY_URL` with the new repository URL):

```sh
git init
git add .
git commit -m "Initial ScopeWeaver 1.0.0rc1"
git branch -M main
git remote add origin YOUR_REPOSITORY_URL
git push -u origin main
```

Do not point these commands at an existing repository without reviewing its current branch,
history and settings. No existing repository, access policy or visibility was changed while
preparing this source distribution.
