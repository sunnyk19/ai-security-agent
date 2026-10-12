<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

  <p align="center">A progressive <a href="http://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>
    <p align="center">
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/v/@nestjs/core.svg" alt="NPM Version" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/l/@nestjs/core.svg" alt="Package License" /></a>
<a href="https://www.npmjs.com/~nestjscore" target="_blank"><img src="https://img.shields.io/npm/dm/@nestjs/common.svg" alt="NPM Downloads" /></a>
<a href="https://circleci.com/gh/nestjs/nest" target="_blank"><img src="https://img.shields.io/circleci/build/github/nestjs/nest/master" alt="CircleCI" /></a>
<a href="https://discord.gg/G7Qnnhy" target="_blank"><img src="https://img.shields.io/badge/discord-online-brightgreen.svg" alt="Discord"/></a>
<a href="https://opencollective.com/nest#backer" target="_blank"><img src="https://opencollective.com/nest/backers/badge.svg" alt="Backers on Open Collective" /></a>
<a href="https://opencollective.com/nest#sponsor" target="_blank"><img src="https://opencollective.com/nest/sponsors/badge.svg" alt="Sponsors on Open Collective" /></a>
  <a href="https://paypal.me/kamilmysliwiec" target="_blank"><img src="https://img.shields.io/badge/Donate-PayPal-ff3f59.svg" alt="Donate us"/></a>
    <a href="https://opencollective.com/nest#sponsor"  target="_blank"><img src="https://img.shields.io/badge/Support%20us-Open%20Collective-41B883.svg" alt="Support us"></a>
  <a href="https://twitter.com/nestframework" target="_blank"><img src="https://img.shields.io/twitter/follow/nestframework.svg?style=social&label=Follow" alt="Follow us on Twitter"></a>
</p>
  <!--[![Backers on Open Collective](https://opencollective.com/nest/backers/badge.svg)](https://opencollective.com/nest#backer)
  [![Sponsors on Open Collective](https://opencollective.com/nest/sponsors/badge.svg)](https://opencollective.com/nest#sponsor)-->

## Description

NestJS backend that reads public or authorized GitHub repositories and detects
basic project information from repository metadata, root files, and common
manifest files.

## Project setup

```bash
npm install
npm run start:dev
```

Public repository analysis and scans work without credentials. Repository listing
uses GitHub's authenticated-user endpoint and requires `GITHUB_TOKEN`; private
repository analysis also requires a token with access. Copy `.env.example` to
`.env` and set the token there; `.env` is gitignored. Without a token the backend
still starts, while repository listing returns an authentication error.

## Compile and run the project

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Run tests

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## GitHub API

- `GET /repositories/test` analyzes `nestjs/nest` by default.
- `GET /repositories/:owner/:repository/analyze` analyzes the specified repository.

The test repository can be changed with `TEST_REPOSITORY_OWNER` and
`TEST_REPOSITORY_NAME`. The response includes repository metadata, recursive
folder and file paths, likely important source files, detected languages and
frameworks, the parsed root `package.json`, production, development, peer, and
optional dependencies, package manager, and manifest paths. GitHub may truncate trees
for very large repositories; this is reported through `treeTruncated`.

## Security scan

- `POST /repositories/test/scan` scans the configured test repository.
- `POST /repositories/:owner/:repository/scan` scans a selected repository.
- `GET /repositories/scan-history?limit=20` returns recent persisted scan summaries.

The scanner performs read-only repository checks against the selected branch and
returns an aggregate security report. It detects hardcoded secrets, unsafe
`eval`/`Function` patterns, unsafe command execution, and basic misconfiguration
patterns in source files, while also running Semgrep rules when the CLI is
installed and `npm audit` separately for each project containing a
`package.json` and `package-lock.json` or `npm-shrinkwrap.json`. Generated and
dependency directories are excluded from project discovery.
Repository files are limited to the first 100 JavaScript/TypeScript files and are
removed from a temporary workspace after scanning. Pattern-based secret and static
checks cover those selected JavaScript/TypeScript files; they do not replace a full
repository-wide security review. Credential-like text in finding evidence is
redacted before the API response, and finding evidence is omitted from scan history.
Dependency audit does not install packages or run lifecycle scripts. Each scanner
reports whether it completed, was skipped, or is unavailable.

## Security dashboard

The React dashboard is in `client/` and the NestJS source is in `server/`.
The dashboard uses the existing NestJS API. Start
the backend with `npm run start:dev`, then start the dashboard in a second
terminal:

```bash
cd client
npm install
npm run dev
```

The Vite development proxy forwards `/api` requests to `http://localhost:3001`.
Set `API_PROXY_TARGET` in `client/.env` if the backend uses another address.
Repository listing uses the backend's authenticated GitHub API; configure
`GITHUB_TOKEN` only in the backend `.env` to list private repositories. The
token is never sent to the browser. The scan endpoint accepts an optional
`{ "branch": "branch-name" }` JSON body and defaults to the repository's
default branch when omitted.

Successful scan reports are persisted in `data/scan-history.json` by default;
set `SCAN_HISTORY_PATH` to choose another server-side path. The store retains at
most 100 records, serializes writes atomically, and omits finding evidence so
source snippets are not written to disk. This is a single-instance local store,
not a multi-replica database. The history endpoint has no per-user application
authorization, like the existing scan endpoints; keep the API behind a trusted
network or an authenticated reverse proxy. Do not enable public access to scan
history for private repositories.

### Semgrep CLI

Semgrep is optional at runtime and reports `unavailable` when its CLI or the
project rules file is absent. On Windows, install it in a project-local virtual
environment so Semgrep does not need a system-wide installation.

Python is required to create the virtual environment. If Python is not already
installed, get it from python.org or install with `winget`:

```powershell
winget install Python.Python.3.12 --accept-source-agreements --accept-package-agreements
```

Then create the venv and install Semgrep:

```powershell
python -m venv .venv-semgrep
.\.venv-semgrep\Scripts\python.exe -m pip install --upgrade pip
.\.venv-semgrep\Scripts\python.exe -m pip install semgrep
.\.venv-semgrep\Scripts\semgrep.exe --version
```

The backend checks `SEMGREP_PATH`, then `.venv-semgrep\Scripts/semgrep.exe`,
then `PATH`. To use a different executable path, set `SEMGREP_PATH` in the
backend process environment (an absolute path is recommended). No global PATH
change is required. Verify the CLI before scanning. A real invocation from the
project root is:

```powershell
.\.venv-semgrep\Scripts\semgrep.exe scan --config .semgrep.yml --json --metrics=off <temporary-scan-workspace>
```

The scanner does not install Semgrep automatically. npm audits require a
`package.json` and `package-lock.json` or `npm-shrinkwrap.json` in the same
project directory. A project missing its lockfile is reported as `skipped` with
`findings: null`; it is not counted as a zero-vulnerability audit. Generate and
commit lockfiles in each npm project to enable those audits.

#### Scanner status semantics

Each scanner reports one of `completed`, `partial`, `skipped`, `unavailable`, or
`failed`. A scanner that did not run reports `findings: null`, never `0`, so a
scan with no completed scanners is not mistaken for a clean scan. npm audit
aggregates per-project statuses: a project missing its lockfile is `skipped`
with `findings: null`; a project whose audit failed is `failed` with
`findings: null`; only a successful audit reports a count. When some projects
succeed and others fail, the aggregate status is `partial` and
`findings: null` at the aggregate level.

### Environment and deployment

Backend variables belong in the ignored root `.env`: `GITHUB_TOKEN` (required
for authenticated repository listing/private access), `PORT` (default 3000),
`TEST_REPOSITORY_OWNER`, `TEST_REPOSITORY_NAME`, and optionally
`OPENAI_API_KEY`, `OPENAI_MODEL`, and `OPENAI_BASE_URL`. Never place GitHub or
OpenAI credentials in `client/.env` or any `VITE_*` variable.

### GitHub Actions CI/CD

Two workflows live under `.github/workflows/`:

- **`.github/workflows/ci.yml`** — runs on `push` to `main` and `pull_request`
  targeting `main`. It lints, builds, and tests both the NestJS backend
  (`server/`) and the React dashboard (`client/`). Artifacts are uploaded for
  downstream jobs.
- **`.github/workflows/security-scan.yml`** — runs on `workflow_dispatch`,
  `push` to `main`, and `pull_request` targeting `main`. It installs Semgrep,
  builds the backend, and executes the existing scanner through
  `server/src/security-scan-cli.ts`, which reuses the compiled
  `SecurityScannerService`. The scan report is published as an artifact and the
  job fails if any scanner reports a `failed` status.

#### Required permissions and secrets

- Set the repository workflow token to **Read** for `contents` and `actions`.
- No custom secrets are required: the scan uses the built-in
  `${{ secrets.GITHUB_TOKEN }}`, which is least-privilege and scoped to the
  current repository. It is never logged.
- Forked pull requests do not run the security scan to avoid running untrusted
  code with a privileged token; use `workflow_dispatch` on the base repository
  instead.

#### Running a workflow manually

Open the **Actions** tab, select **Security Scan**, and choose **Run workflow**.
Optionally pass `owner/repository` (e.g. `nestjs/nest`) and a `branch`; the
default is the current repository's default branch.

#### Automatic triggers

- `push` to `main` runs both workflows.
- `pull_request` targeting `main` runs both workflows; the security scan is
  skipped for forks.
- Concurrent runs on the same ref are cancelled to avoid duplicate executions.

#### Inspecting failures and scan results

- Failed jobs show the failing step inline. The security scan uploads
  `security-scan-report` containing `scan-report.json` and `scan-stderr.log`.
- A scan is treated as failed when any scanner reports `failed` (Semgrep, npm
  audit, secret detection, or static analysis). A scan with skipped or
  unavailable scanners is not treated as clean.
- Local preview: build the backend (`npm run build` at the root), then run
  `SCAN_TARGET_OWNER=<owner> SCAN_TARGET_REPO=<repo> [SCAN_TARGET_BRANCH=<branch>] [GITHUB_TOKEN=<token>] node dist/security-scan-cli.js`.

For deployment, build `client/` with `npm run build` from that directory and
serve its `dist/` assets through the chosen web server. Run the NestJS app from
the project root with `npm run build` and `npm run start:prod`; configure the
production reverse proxy to forward `/repositories` to NestJS and provide a
same-origin API base or appropriate `VITE_API_BASE_URL` at frontend build time.
Keep `.env` outside source control and provide secrets through the deployment
platform's secret manager.

### Production setup checklist

Before deploying, complete these steps once per environment:

1. **Install dependencies** at the project root with `npm install`, then again
   inside `client/` with `npm install`.
2. **Install Semgrep** in the project-local virtual environment so the scanner
   is available at runtime (see the Semgrep CLI section above). Set
   `SEMGREP_PATH` to the absolute path of the executable if you place it
   outside `.venv-semgrep/`.
3. **Provide secrets through the environment**:
   - `GITHUB_TOKEN` — required for authenticated repository listing and private
     repository access. Never place it in `client/.env` or any `VITE_*`
     variable.
   - `OPENAI_API_KEY`, `OPENAI_MODEL`, and optionally `OPENAI_BASE_URL` for AI
     analysis features.
   - `PORT` (default `3000`) and `SCAN_HISTORY_PATH` (default
     `data/scan-history.json`) if non-default values are needed.
4. **Verify the scanners** by running a scan against the configured test
   repository (`POST /repositories/test/scan`) and confirming that Semgrep,
   npm audit, and secret detection each report a status of `completed`.
5. **Build both apps**: `npm run build` at the root for the NestJS backend, and
   `npm run build` inside `client/` for the React dashboard.
6. **Run the test suite**: `npm run test` and `npm run test:e2e` at the root,
   and `npm run test` inside `client/`.
7. **Run lint**: `npm run lint` at the root, and `npm run lint` inside `client/`.
8. **Start the backend** with `npm run start:prod` and serve the frontend
   `client/dist/` through a static host or reverse proxy.

## AI analysis

`POST /repositories/:owner/:repository/analyze-finding` accepts one scanner
finding as JSON and returns structured root-cause analysis. Configure
`OPENAI_API_KEY`, `OPENAI_MODEL`, and optionally `OPENAI_BASE_URL` in `.env`.
Source context is redacted for common credential patterns before it is sent to
the configured OpenAI-compatible endpoint.

`POST /repositories/:owner/:repository/generate-fix` accepts a finding and its
analysis and returns a proposed replacement for the affected file. It does not
write to GitHub or mark the proposal verified.

## Deployment

When you're ready to deploy your NestJS application to production, there are some key steps you can take to ensure it runs as efficiently as possible. Check out the [deployment documentation](https://docs.nestjs.com/deployment) for more information.

If you are looking for a cloud-based platform to deploy your NestJS application, check out [Mau](https://mau.nestjs.com), our official platform for deploying NestJS applications on AWS. Mau makes deployment straightforward and fast, requiring just a few simple steps:

```bash
$ npm install -g @nestjs/mau
$ mau deploy
```

With Mau, you can deploy your application in just a few clicks, allowing you to focus on building features rather than managing infrastructure.

## Observability

In production applications, observability is essential for understanding how your system behaves, detecting issues early, and maintaining reliable performance.

[NestJS Observe](https://observe.nestjs.com) automatically instruments your NestJS application, giving you deep visibility into your system with minimal setup:

- **Distributed tracing:** Follow requests across services and understand how they flow through your system.
- **Waterfall analysis:** Visualize request execution and identify slow operations, bottlenecks, and unexpected delays.
- **Performance analysis:** Analyze application performance in real time and quickly pinpoint areas that need optimization.
- **Metrics:** Track key application and infrastructure metrics to understand system health and performance trends.
- **Logging:** Centralize and correlate logs with traces and other telemetry to make debugging easier.
- **Error tracking:** Detect errors quickly and investigate their root causes with the surrounding context.
- **SLA monitoring:** Track service-level objectives and identify when your application is approaching or exceeding defined thresholds.
- **Alarms and alerts:** Set up alerts for critical errors, performance degradation, SLA violations, and other anomalies so your team can react quickly.

## Resources

Check out a few resources that may come in handy when working with NestJS:

- Visit the [NestJS Documentation](https://docs.nestjs.com) to learn more about the framework.
- For questions and support, please visit our [Discord channel](https://discord.gg/G7Qnnhy).
- To dive deeper and get more hands-on experience, check out our official video [courses](https://courses.nestjs.com/).
- Deploy your application to AWS with the help of [NestJS Mau](https://mau.nestjs.com) in just a few clicks.
- Auto-instrument your application with [NestJS Observer](https://observer.nestjs.com). Distributed tracing, metrics, and logging made easy. Error tracking and performance monitoring for your NestJS applications.
- Visualize your application graph and interact with the NestJS application in real-time using [NestJS Devtools](https://devtools.nestjs.com).
- Need help with your project (part-time to full-time)? Check out our official [enterprise support](https://enterprise.nestjs.com).
- To stay in the loop and get updates, follow us on [X](https://x.com/nestframework) and [LinkedIn](https://linkedin.com/company/nestjs).
- Looking for a job, or have a job to offer? Check out our official [Jobs board](https://jobs.nestjs.com).

## Support

Nest is an MIT-licensed open source project. It can grow thanks to the sponsors and support by the amazing backers. If you'd like to join them, please [read more here](https://docs.nestjs.com/support).

## Stay in touch

- Author - [Kamil Myśliwiec](https://twitter.com/kammysliwiec)
- Website - [https://nestjs.com](https://nestjs.com/)
- Twitter - [@nestframework](https://twitter.com/nestframework)

## License

Nest is [MIT licensed](https://github.com/nestjs/nest/blob/master/LICENSE).
