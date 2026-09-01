# PAYO production Devnet boundary

The pinned Starknet privacy SDK declares `starknet-devnet` as a production
dependency even though only its Node-only `./testing/devnet` module imports it.
PAYO does not import that testing surface; its Devnet gates use the separately
pinned external binary recorded in `toolchains.lock.json`.

This local package replaces that unused downloader/process dependency in the
production dependency graph. It deliberately fails closed if
`Devnet.spawnInstalled()` is ever called. The privacy SDK tarball and all of its
runtime files remain unchanged.
