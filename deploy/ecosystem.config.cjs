module.exports = {
  apps: [
    {
      name: "kovanica-node",
      cwd: process.env.KOVANICA_NODE_DIR || ".",
      script: "./target/release/kovanica-node",
      args: "explorer 127.0.0.1:8080",
      interpreter: "none",
      autorestart: true,
      max_restarts: 20,
      env: {
        KOVANICA_MINE: "0",
        KOVANICA_FAUCET: "0",
        KOVANICA_ALLOW_RESET: "0",
        KOVANICA_OPERATOR: "0",
        KOVANICA_POW: "1",
        KOVANICA_LISTEN: "0.0.0.0:9000",
      },
    },
  ],
};
