# `webauthn` - PostgreSQL WebAuthn Server

`webauthn` is a pure SQL PostgreSQL extension implementing the [WebAuthn protocol](https://en.wikipedia.org/wiki/WebAuthn)
used by modern browsers for credential creation and assertion
using a U2F Token, like those provided by Yubico,
or using Built-in sensors, as seen in the Chrome example below.

![layout](https://i.imgur.com/1KXVbTb.png)
![layout](https://i.imgur.com/KPF6vEg.png)

## Dependencies

[pgcrypto](https://www.postgresql.org/docs/current/pgcrypto.html) for the [digest()](https://www.postgresql.org/docs/current/pgcrypto.html#id-1.11.7.34.6) and [gen_random_bytes()](https://www.postgresql.org/docs/current/pgcrypto.html#id-1.11.7.34.10) functions.

[pguecc](https://github.com/ameensol/pg-ecdsa) for the ECDSA cryptographic [ecdsa_verify()](https://github.com/ameensol/pg-ecdsa#ecdsa_verifypublic_key-textbytea-input_data-bytea-signature-textbytea-hash_func-text-curve_name-text) function.

[PostgREST](https://postgrest.org/en/v7.0.0/) to provide a web service API for browsers to use.

## Installation

Install the `webauthn` extension with:

    $ git clone https://github.com/truthly/pg-webauthn.git
    $ cd pg-webauthn
    $ make install
    $ make installcheck

Note that the Postgres development tools and a C compiler must be installed
(the postgresql-dev or similar package) and the ``pgcrypto`` extension must
be included in the Postgres distribution (it's generally included by default;
if not, the error will mention "could not open extension control file
".../pgcrypto.control").

## Usage

Use with:

    $ psql
    # CREATE EXTENSION webauthn CASCADE;
    NOTICE:  installing required extension "pguecc"
    NOTICE:  installing required extension "pgcrypto"
    CREATE EXTENSION;

## API

The public API consists of four functions, two for sign-up and two for sign-in.

- [Sign-up functions](https://github.com/truthly/pg-webauthn#sign-up-api-functions)
  - [webauthn.init_credential()](https://github.com/truthly/pg-webauthn#webauthninit_credentialusername-text-returns-jsonb)
  - [webauthn.make_credential()](https://github.com/truthly/pg-webauthn#webauthnmake_credentialusername-text-challenge-base64-credential_raw_id-base64-credential_type-text-attestation_object-base64-client_data_json-base64-returns-boolean)
- [Sign-in functions](https://github.com/truthly/pg-webauthn#sign-in-api-functions)
  - [webauthn.get_credentials()](https://github.com/truthly/pg-webauthn#webauthnget_credentialsusername-text-returns-jsonb)
  - [webauthn.verify_assertion()](https://github.com/truthly/pg-webauthn#webauthnverify_assertioncredential_raw_id-base64-credential_type-text-authenticator_data-base64-client_data_json-base64-signature-base64-user_handle-base64-returns-boolean)

### Sign-up API functions

To sign-up, the browser first calls `webauthn.init_credential()` to get a list of supported crypto algorithms together with a random challenge to be used in the subsequent `webauthn.make_credential()` call to save the public key credential generated by the browser.

**`webauthn.init_credential(username text) RETURNS jsonb`**

Generates a random challenge stored to the [webauthn.challenges](https://github.com/truthly/pg-webauthn/blob/master/TABLES/challenges.sql) table.
Returns a json object compatible with the browser `navigator.credentials.create()` method,
where the only key, `publickey`, contains a [PublicKeyCredentialCreationOptions](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions) object.

Via `psql` prompt:

```sql
SELECT webauthn.init_credential(username := 'test')
```

Via `PostgREST` API:

```shell
curl 'http://localhost/api/rpc/init_credential' \
  -H 'Content-Type: application/json;charset=utf-8' \
  --data '{"username":"test"}'
```

```json
{
    "publicKey": {
        "rp": {
            "id": "localhost",
            "name": "localhost"
        },
        "user": {
            "id": "dGVzdA==",
            "name": "test",
            "displayName": "test"
        },
        "timeout": 60000,
        "challenge": "543amzXbkpA/g0DnFcvFvAybXBzwMg57fGed37YB8kM=",
        "extensions": {
            "txAuthSimple": ""
        },
        "attestation": "none",
        "pubKeyCredParams": [
            {
                "alg": -7,
                "type": "public-key"
            }
        ],
        "authenticatorSelection": {
            "userVerification": "discouraged",
            "requireResidentKey": false
        }
    }
}
```

**`webauthn.make_credential(username text, challenge base64, credential_raw_id base64, credential_type text, attestation_object base64, client_data_json base64) RETURNS boolean`**

Stores the public key for the credential generated by the browser to the [webauthn.credentials](https://github.com/truthly/pg-webauthn/blob/master/TABLES/credentials.sql) table.
The function also verifies there is an unconsumed matching `challenge` for the given `username`,
which is consumed in the same transaction as the credential is stored.
Returns `true` if successful.

Via `psql` prompt:

```sql
SELECT make_credential(
  username := 'test',
  challenge := '543amzXbkpA/g0DnFcvFvAybXBzwMg57fGed37YB8kM=',
  credential_raw_id := 'AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA==',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViySZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFX80iUq3OAAI1vMYKZIsLJfHwVQMALgFIH6eQeaDqHJBseLABTk5TEEw6yK+45NhmdLOnUhGn5hmZHQS4BbTeS+ukHHilAQIDJiABIVggq5dcFvA47Q1wjcY8u269gS1IwG+L9cbRIkkB5NpsHdIiWCAe50J8KlNFD/SNq6ajrh0nWhvU4bNED3rceNaGPLkPEQ==',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNTQzYW16WGJrcEFfZzBEbkZjdkZ2QXliWEJ6d01nNTdmR2VkMzdZQjhrTSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9'
);
```

Via `PostgREST` API:

```shell
curl 'http://localhost/api/rpc/make_credential' \
  -H 'Content-Type: application/json;charset=utf-8' \
  --data '{"username":"test","challenge":"543amzXbkpA/g0DnFcvFvAybXBzwMg57fGed37YB8kM=","credential_raw_id":"AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA==","credential_type":"public-key","attestation_object":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViySZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFX80iUq3OAAI1vMYKZIsLJfHwVQMALgFIH6eQeaDqHJBseLABTk5TEEw6yK+45NhmdLOnUhGn5hmZHQS4BbTeS+ukHHilAQIDJiABIVggq5dcFvA47Q1wjcY8u269gS1IwG+L9cbRIkkB5NpsHdIiWCAe50J8KlNFD/SNq6ajrh0nWhvU4bNED3rceNaGPLkPEQ==","client_data_json":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNTQzYW16WGJrcEFfZzBEbkZjdkZ2QXliWEJ6d01nNTdmR2VkMzdZQjhrTSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"}'
```

```json
true
```

### Sign-in API functions

To sign-in, the browser first calls `webauthn.get_credentials()` to get a list of allowed credentials for the given `username` together with a random challenge to be used in the subsequent `webauthn.verify_assertion()` call to verify the signature generated by the browser.

**`webauthn.get_credentials(username text) RETURNS jsonb`**

Returns the public key credentials created by the `webauthn.make_credential()` function
stored in the [webauthn.credentials](https://github.com/truthly/pg-webauthn/blob/master/TABLES/credentials.sql) table.

Generates a random challenge stored to the [webauthn.challenges](https://github.com/truthly/pg-webauthn/blob/master/TABLES/challenges.sql) table.

The returned json object is compatible with the browser `navigator.credentials.get()` method,
where the only key, `publickey`, contains a [PublicKeyCredentialRequestOptions](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions) object.

Via `psql` prompt:

```sql
SELECT get_credentials(username := 'test');
```

Via `PostgREST` API:

```shell
curl 'http://localhost/api/rpc/get_credentials' \
  -H 'Content-Type: application/json;charset=utf-8' \
  --data '{"username":"test"}'
```

```json
{
    "publicKey": {
        "rpId": "localhost",
        "timeout": 60000,
        "challenge": "WF3eKLvgsC+mioYSS50nNMh/FpIzXLdx7+1wMOPsJ9Y=",
        "extensions": {
            "txAuthSimple": ""
        },
        "allowCredentials": [
            {
                "id": "AfwHV5nY2V4dFio6szj4UFoVlmTr2Y4Pdmu9wRBuZ9Sx16//w7K3llmpVV73EQ==",
                "type": "public-key"
            }
        ],
        "userVerification": "required"
    }
}
```

**`webauthn.verify_assertion(credential_raw_id base64, credential_type text, authenticator_data base64, client_data_json base64, signature base64, user_handle base64) RETURNS boolean`**

Verifies the `signature` is valid for the credential matching `credential_raw_id`, `credential_type` and the `client_data_json->>'challenge'`.

Stores the input data and the result of the verify operation to the [webauthn.assertions](https://github.com/truthly/pg-webauthn/blob/master/TABLES/assertions.sql) table.

Returns `true` upon success.

Via `psql` prompt:

```sql
SELECT verify_assertion(
  credential_raw_id := 'AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA==',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFX80ilw==',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVER5RnF4N2lwUS1Vb0otT3ZnWlVtV2ticHpPRlJtNk44WFY2bW93Sk9nUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==',
  signature := 'MEUCIQD/y94itkRZrRcu5fQMplWcDorpCmpJ9YpnQvVgR/r5yAIgSy0nBbyWxFjH60R0u7ca27z4Ds/PiiycaYOeQxoB0nw=',
  user_handle := 'dGVzdA=='
);
```

Via `PostgREST` API:

```shell
curl 'http://localhost/api/rpc/verify_assertion' \
  -H 'Content-Type: application/json;charset=utf-8' \
  --data '{"credential_raw_id":"AUgfp5B5oOockGx4sAFOTlMQTDrIr7jk2GZ0s6dSEafmGZkdBLgFtN5L66QceA==","credential_type":"public-key","authenticator_data":"SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFX80ilw==","client_data_json":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVER5RnF4N2lwUS1Vb0otT3ZnWlVtV2ticHpPRlJtNk44WFY2bW93Sk9nUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==","signature":"MEUCIQD/y94itkRZrRcu5fQMplWcDorpCmpJ9YpnQvVgR/r5yAIgSy0nBbyWxFjH60R0u7ca27z4Ds/PiiycaYOeQxoB0nw=","user_handle":"dGVzdA=="}'
```

```json
true
```
