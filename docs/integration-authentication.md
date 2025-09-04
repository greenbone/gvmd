# Authentication Methods in gvmd (HTTP Scanner & Agent Controller)

The current `gvmd` implementation supports two authentication methods for communication with external components like the **HTTP Scanner** and the **Agent Controller**.

## Supported Methods

- **Certificates (mTLS)**
- **API Key–like tokens** (`X-API-KEY` or `Authorization: Bearer`)

---

## 1. Certificates (mTLS)

This method uses **X.509 certificates**, where access is controlled based on a Certificate Authority (CA).  
Certificates are configured on the scanner, and `gvmd` uses them to establish a mutual TLS connection.

### Certificate Creation for mTLS

To set up certificate-based authentication, you need a CA certificate and client/server certificates.  
The `openvas-scanner` repository provides helper scripts and examples to generate these:

- Create a CA certificate
- Generate server and client certificates signed by this CA
- Configure gvmd and the scanner with the generated files

Detailed examples and scripts are available here:  
[openvas-scanner: rust/examples/tls](https://github.com/greenbone/openvas-scanner/tree/main/rust/examples/tls)

### Example: Configure certificates for a scanner

```bash
gvmd --modify-scanner <scanner_uuid> \
  --scanner-ca-pub=server.pem \
  --scanner-key-pub=client.pem \
  --scanner-key-priv=client.rsa \
  --scanner-host="localhost" \
  --scanner-port=<port>
```

---

## 2. API Key–like Tokens

This method uses a static token that must be provided with each request.
Depending on the component, the token is included in the request header as either:

* **HTTP Scanner:** `X-API-KEY: <token>`
* **Agent Controller:** `Authorization: Bearer <token>`

Both behave the same way for authentication/authorization.

### Example: HTTP Scanner request with API Key

```c
if (apikey)
  {
    GString *xapikey = g_string_new ("X-API-KEY: ");
    g_string_append (xapikey, apikey);

    if (!gvm_http_add_header (headers, xapikey->str))
      g_warning ("%s: Not possible to set API-KEY", __func__);

    g_string_free (xapikey, TRUE);
  }
```

HTTP Header example:

```http
X-API-KEY: <your_api_key_here>
```

---

### Example: Agent Controller request with Bearer Token

```c
if (bearer_token && *bearer_token)
  {
    GString *auth = g_string_new ("Authorization: Bearer ");
    g_string_append (auth, bearer_token);

    if (!gvm_http_add_header (headers, auth->str))
      g_warning ("%s: Failed to set Authorization header", __func__);

    g_string_free (auth, TRUE);
  }
```

HTTP Header example:

```http
Authorization: Bearer <your_bearer_token_here>
```

---

## Notes

* For the **HTTP Scanner**, both **Certificates (mTLS)** and **API Key** are supported.
* For the **Agent Controller**, **API Key–like tokens** are currently used (via `Authorization: Bearer`).
* Authentication modes are configured either via **configuration files** or by passing arguments when starting `gvmd`.