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

Public repositories work without credentials. Set `GITHUB_TOKEN` to analyze
private repositories or to increase GitHub API rate limits. Copy `.env.example`
to `.env` and set the token there; `.env` is gitignored.

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

The scanner performs read-only repository checks against the selected branch and
returns an aggregate security report. It detects hardcoded secrets, unsafe
`eval`/`Function` patterns, unsafe command execution, and basic misconfiguration
patterns in source files, while also running Semgrep rules when the CLI is
installed and `npm audit` separately for each project containing a
`package.json` and `package-lock.json` or `npm-shrinkwrap.json`. Generated and
dependency directories are excluded from project discovery.
Repository files are limited to the first 100 JavaScript/TypeScript files and are
removed from a temporary workspace after scanning. Dependency audit does not install
packages or run lifecycle scripts. Each scanner reports whether it completed,
was skipped, or is unavailable.

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

### Semgrep CLI

Semgrep is optional at runtime and reports `unavailable` when its CLI or the
project rules file is absent. On Windows, install it in WSL rather than exposing
the host environment to scanned repository code:

```powershell
wsl --install -d Ubuntu
```

After installing/restarting WSL, open Ubuntu and run:

```bash
sudo apt update
sudo apt install -y python3 python3-pip pipx
pipx ensurepath
pipx install semgrep
semgrep --version
```

Make the CLI available to the NestJS process (for example, run the backend
inside the same WSL distribution) and verify with `semgrep --version` before
scanning. A real invocation from the project root is:

```bash
semgrep scan --config .semgrep.yml --json --metrics=off <temporary-scan-workspace>
```

The scanner does not install Semgrep automatically. npm audits require a
`package.json` and `package-lock.json` or `npm-shrinkwrap.json` in the same
project directory. A project missing its lockfile is reported as `skipped` with
`findings: null`; it is not counted as a zero-vulnerability audit. Generate and
commit lockfiles in each npm project to enable those audits.

### Environment and deployment

Backend variables belong in the ignored root `.env`: `GITHUB_TOKEN` (required
for authenticated repository listing/private access), `PORT` (default 3000),
`TEST_REPOSITORY_OWNER`, `TEST_REPOSITORY_NAME`, and optionally
`OPENAI_API_KEY`, `OPENAI_MODEL`, and `OPENAI_BASE_URL`. Never place GitHub or
OpenAI credentials in `client/.env` or any `VITE_*` variable.

For deployment, build `client/` with `npm run build` from that directory and
serve its `dist/` assets through the chosen web server. Run the NestJS app from
the project root with `npm run build` and `npm run start:prod`; configure the
production reverse proxy to forward `/repositories` to NestJS and provide a
same-origin API base or appropriate `VITE_API_BASE_URL` at frontend build time.
Keep `.env` outside source control and provide secrets through the deployment
platform's secret manager.

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
