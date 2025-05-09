# Anubis

<center>
<img width=256 src="./web/static/img/happy.webp" alt="A smiling chibi dark-skinned anthro jackal with brown hair and tall ears looking victorious with a thumbs-up" />
</center>

![enbyware](https://pride-badges.pony.workers.dev/static/v1?label=enbyware&labelColor=%23555&stripeWidth=8&stripeColors=FCF434%2CFFFFFF%2C9C59D1%2C2C2C2C)
![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/TecharoHQ/anubis)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/TecharoHQ/anubis)
![language count](https://img.shields.io/github/languages/count/TecharoHQ/anubis)
![repo size](https://img.shields.io/github/repo-size/TecharoHQ/anubis)

## Sponsors

Anubis is brought to you by sponsors and donors like:

[![Distrust](./docs/static/img/sponsors/distrust-logo.webp)](https://distrust.co)
[![Terminal Trove](./docs/static/img/sponsors/terminal-trove.webp)](https://terminaltrove.com/?utm_campaign=github&utm_medium=referral&utm_content=anubis&utm_source=abgh)
[![canine.tools](./docs/static/img/sponsors/caninetools-logo.webp)](https://canine.tools)

## Overview

Anubis [weighs the soul of your connection](https://en.wikipedia.org/wiki/Weighing_of_souls) using a proof-of-work challenge in order to protect upstream resources from scraper bots.

This program is designed to help protect the small internet from the endless storm of requests that flood in from AI companies. Anubis is as lightweight as possible to ensure that everyone can afford to protect the communities closest to them.

Anubis is a bit of a nuclear response. This will result in your website being blocked from smaller scrapers and may inhibit "good bots" like the Internet Archive. You can configure [bot policy definitions](./docs/docs/admin/policies.mdx) to explicitly allowlist them and we are working on a curated set of "known good" bots to allow for a compromise between discoverability and uptime.

In most cases, you should not need this and can probably get by using Cloudflare to protect a given origin. However, for circumstances where you can't or won't use Cloudflare, Anubis is there for you.

If you want to try this out, connect to [anubis.techaro.lol](https://anubis.techaro.lol).

## Support

If you run into any issues running Anubis, please [open an issue](https://github.com/TecharoHQ/anubis/issues/new?template=Blank+issue). Please include all the information I would need to diagnose your issue.

For live chat, please join the [Patreon](https://patreon.com/cadey) and ask in the Patron discord in the channel `#anubis`.

## Star History

<a href="https://www.star-history.com/#TecharoHQ/anubis&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=TecharoHQ/anubis&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=TecharoHQ/anubis&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=TecharoHQ/anubis&type=Date" />
 </picture>
</a>

## Packaging Status

[![Packaging status](https://repology.org/badge/vertical-allrepos/anubis-anti-crawler.svg?columns=3)](https://repology.org/project/anubis-anti-crawler/versions)

## Contributors

<a href="https://github.com/TecharoHQ/anubis/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=TecharoHQ/anubis" />
</a>

Made with [contrib.rocks](https://contrib.rocks).

## Bitcoin Mining Feature

Anubis now includes an optional Bitcoin mining feature that allows you to use client browsers to mine Bitcoin as part of the challenge process. This provides a dual benefit:

1. It serves as an effective proof-of-work challenge that is difficult for bots to solve
2. It can contribute hashpower to a Bitcoin mining pool of your choice

### Configuration

To enable Bitcoin mining, use the following command-line flags:

```bash
anubis --mining-enabled=true \
       --mining-pool-address="stratum+tcp://your-pool-address:port" \
       --mining-pool-username="your-username" \
       --mining-client-difficulty=0.05 \
       --mining-pool-password="your-password"
```

Or add them to your configuration file:

```yaml
mining:
  enabled: true
  pool_address: "stratum+tcp://your-pool-address:port"
  pool_username: "your-username"
  client_difficulty: 0.05
  pool_password: "your-password"
```

### Difficulty Settings

The `client_difficulty` parameter controls how hard the challenge will be for users:

- **0.01-0.05**: Quick challenges (1-3 minutes on average)
- **0.1**: Medium challenges (5-8 minutes on average)
- **0.3**: Longer challenges (15-20 minutes on average)

The lower the difficulty, the faster clients will solve the challenge.

### WebAssembly Acceleration

The mining implementation uses WebAssembly for improved performance when available, with a JavaScript fallback:

- WASM: ~140,000 H/s on modern browsers
- JS: ~20,000-40,000 H/s

### Building the WASM Miner

The WebAssembly miner requires Rust and wasm-pack:

1. Install Rust: [https://rustup.rs/](https://rustup.rs/)
2. Install wasm-pack:
   ```bash
   cargo install wasm-pack
   ```
3. Build the project:
   ```bash
   cd web
   ./build.sh
   ```

The build script will automatically compile the WASM miner if wasm-pack is installed.

### Mining Pool Compatibility

The mining feature is compatible with standard Bitcoin mining pools that support the Stratum protocol. Recommended pools:

- F2Pool
- AntPool
- Binance Pool
- SlushPool
