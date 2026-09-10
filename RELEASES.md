# Publishing prebuilt binaries

The one-click installers (`scripts/install.sh`, `scripts/install.ps1`) prefer a
binary from the **latest GitHub Release**. If no matching asset is found they
fall back to building from source.

## Asset names (required)

| Platform | Asset filename |
| --- | --- |
| Linux x86_64 | `kovanica-node-x86_64-linux.tar.gz` |
| Linux aarch64 | `kovanica-node-aarch64-linux.tar.gz` |
| macOS x86_64 | `kovanica-node-x86_64-macos.tar.gz` |
| macOS arm64 | `kovanica-node-aarch64-macos.tar.gz` |

Each tarball must contain a **single** executable named `kovanica-node`
(no nested directories).

## Build & pack (example)

```sh
# on the target architecture / with cross-compilation
cargo build --release -p kovanica-node

mkdir -p dist
cp target/release/kovanica-node dist/
# Windows: cp target/release/kovanica-node.exe dist/kovanica-node.exe

cd dist
tar -czf kovanica-node-x86_64-linux.tar.gz kovanica-node
# (rename the .tar.gz to match the platform you built for)
```

## Create the GitHub Release

1. Tag a version, e.g. `v0.2.0` (must match `[workspace.package] version` or be intentional).
2. Create a Release on GitHub from that tag.
3. Upload the four (or more) `.tar.gz` assets with the exact names above.
4. The install script uses:

   ```
   https://github.com/KovanicaDAG/kovanica-node/releases/latest/download/<ASSET>.tar.gz
   ```

Until the first Release with assets exists, every install falls back to source
build — that is expected and works.

## Optional: GitHub Actions

You can add a release workflow that builds on `ubuntu-latest`, `macos-latest`,
and (with care) cross targets, then uploads the assets. Keep the asset names
identical to the table above so the install scripts stay unchanged.
