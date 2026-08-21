# Optional: put nginx in front of a local explorer

The node binds loopback. Example for `explorer.example.com`:

```nginx
# see nginx-explorer.conf — proxy_pass http://127.0.0.1:8080
```

```sh
cargo build --release -p kovanica-node
./target/release/kovanica-node explorer 127.0.0.1:8080
```

Open **9000/tcp** if you want TCP peers. Do not bind the explorer on `0.0.0.0` unless you intend it to be public.
