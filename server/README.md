# Local HTTPS for htbx-auth server

This server can run over HTTPS on localhost using a self-signed development certificate. WebSocket upgrades continue to work over wss when HTTPS is enabled.

## Options

- HTTPS is enabled when the environment variable `HTTPS=true` and a key/cert are available.
- Paths to the key/cert default to:
  - `server/certs/localhost-key.pem`
  - `server/certs/localhost-cert.pem`
- You can override with:
  - `SSL_KEY_PATH` — absolute or relative path to the private key (PEM)
  - `SSL_CERT_PATH` — absolute or relative path to the certificate (PEM)

## MongoDB Setup

This server now uses MongoDB via Mongoose for all user and token storage. You need a running MongoDB instance (local or cloud).

### Local MongoDB (Windows)

1. Download and install MongoDB Community Server: https://www.mongodb.com/try/download/community
2. Start MongoDB (default port 27017):

```
"C:\Program Files\MongoDB\Server\<version>\bin\mongod.exe"
```

3. The server will connect to `mongodb://localhost:27017/htbx-auth` by default. You can override with the `MONGO_URI` environment variable.

### Cloud MongoDB (Atlas)

1. Create a free cluster at https://www.mongodb.com/cloud/atlas
2. Get your connection string and set it as `MONGO_URI` in your environment.

## Generate a local certificate (Windows)

Choose one method:

### A) mkcert (recommended)

1. Install Chocolatey (if you don't have it): https://chocolatey.org/install
2. In an elevated PowerShell:

```
choco install mkcert nss-tools -y
```

3. Create a local CA and certs inside `server/certs`:

```
# From the project root
mkdir server\certs -Force
mkcert -install
mkcert -key-file server\certs\localhost-key.pem -cert-file server\certs\localhost-cert.pem localhost 127.0.0.1 ::1
```

4. Start the server with HTTPS:

```
# PowerShell
$env:HTTPS = "true"; node server/index.js
```

### B) OpenSSL (if you can't use mkcert)

```
# From project root
mkdir server\certs -Force
openssl req -x509 -nodes -newkey rsa:2048 -days 825 -keyout server\certs\localhost-key.pem -out server\certs\localhost-cert.pem -subj "/CN=localhost"
```

Then run:

```
$env:HTTPS = "true"; node server/index.js
```

If you used OpenSSL, you'll likely need to accept the certificate in your browser (it won't be trusted by default).

## CORS and client

- CORS allows both `http://localhost:3000` and `https://localhost:3000`.
- When HTTPS is enabled on the server, your WebSocket URLs should use `wss://`.

## Troubleshooting

- If you see `Not allowed by CORS`, confirm the client origin is exactly `http://localhost:3000` or `https://localhost:3000`.
- If HTTPS doesn't start, ensure `HTTPS=true` and both key/cert files exist or set `SSL_KEY_PATH` and `SSL_CERT_PATH` to valid PEM files.
