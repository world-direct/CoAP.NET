# Future improvements

- Enable RSA Certificates
- Load own Certificate Chain from store
- PSK client authorization

# Examples

## CoAP Server Config Unsecure
```
    "Coap": {
      "Endpoints": {
        "CoAP": {
          "Url": "coap://*:5683"
        }
      }
    }
```

## CoAPS Server Config with Certificate from pfx file without client authentication
```
    "Coap": {
      "Endpoints": {
        "CoAPS": {
          "Url": "coaps://*:5684",
          "Certificate": {
            "Path": "server.pfx",
            "Password": "$CREDENTIAL_PLACEHOLDER$"
          }
        }
      }
    }
```

## CoAPS Server Config with Certificate from .pem and encrypted .key file without client authentication
```
    "Coap": {
      "Endpoints": {
        "CoAPS": {
          "Url": "coaps://*:5684",
          "Certificate": {
            "Path": "server-cert.pem",
            "KeyPath": "server-key.key"
            "Password": "$CREDENTIAL_PLACEHOLDER$"
          }
        }
      }
    }
```

## CoAPS Server Config with Certificate from store without client authentication
```
    "Coap": {
      "Endpoints": {
        "CoAPS": {
          "Url": "coaps://*:5684",
          "Certificate": {
            "Subject": "ls1.argus.dev.energy.loc",
            "Store": "<certificate store; required>",
            "Location": "<location; defaults to CurrentUser>",
            "AllowInvalid": "<true or false; defaults to false>"
          }
        }
      }
    }
```
