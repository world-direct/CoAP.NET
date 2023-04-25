# Future improvements

- Enable RSA Certificates
- Load own Certificate Chain from store
- PSK client authorization

# Examples

## CoAP Server Config Unsecure
``` json
    "Coap": {
      "Endpoints": {
        "CoAP": {
          "Url": "coap://*:5683"
        }
      }
    }
```

## CoAPS Server Config with Certificate from pfx file without client authentication
``` json
    "Coap": {
      "Endpoints": {
        "CoAPS": {
          "Url": "coaps://*:5684",
          "Certificate": {
            "Path": "server.pfx",
            "Password": "$CREDENTIAL_PLACEHOLDER$"
          },
          "HandshakeTimeout": "00:01:00"
        }
      }
    }
```

## CoAPS Server Config with Certificate from .pem and encrypted .key file without client authentication
``` json
    "Coap": {
      "Endpoints": {
        "CoAPS": {
          "Url": "coaps://*:5684",
          "Certificate": {
            "Path": "server-cert.pem",
            "KeyPath": "server-key.key"
            "Password": "$CREDENTIAL_PLACEHOLDER$"
          },
          "HandshakeTimeout": "00:01:00"
        }
      }
    }
```

## CoAPS Server Config with Certificate from store without client authentication
``` json
    "Coap": {
      "Endpoints": {
        "CoAPS": {
          "Url": "coaps://*:5684",
          "Certificate": {
            "Subject": "ls1.argus.dev.energy.loc",
            "Store": "<certificate store; required>",
            "Location": "<location; defaults to CurrentUser>",
            "AllowInvalid": "<true or false; defaults to false>"
          },
          "HandshakeTimeout": "00:01:00"
        }
      }
    }
```

## CoAPS Server Config with Certificate from pfx file and CA from file
``` json
    "Coap": {
      "Endpoints": {
        "CoAP": {
          "Url": "coaps://*:5684",
          "Certificate": {
            "Path": "server.p12",
            "Password": "lukas!"
          },
          "ClientCA": {
              "Path": "ca-cert.pem"
          },
          "HandshakeTimeout": "00:01:00"
        }
      }
    }
```