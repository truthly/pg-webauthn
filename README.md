<h1 id="top">🔐🐘<code>webauthn</code></h1>

1. [About](#about)
1. [Dependencies](#dependencies)
1. [Installation](#installation)
1. [Usage](#usage)
1. [Public API](#public-api)
    1. [Sign-up functions](#sign-up)
        1. [webauthn.init_credential()]
        1. [webauthn.make_credential()]
    1. [Sign-in functions](#sign-in)
        1. [webauthn.get_credentials()]
        1. [webauthn.verify_assertion()]

[webauthn.init_credential()]: #init-credential
[webauthn.make_credential()]: #make-credential
[webauthn.get_credentials()]: #get-credentials
[webauthn.verify_assertion()]: #verify-assertion

<h2 id="about">1. About</h2>

`webauthn` is a pure SQL [PostgreSQL] extension implementing the [WebAuthn] protocol
used by modern browsers for credential creation and assertion
using a [U2F Token], like those provided by [Yubico],
or using Built-in sensors, as seen in the [Chrome] example below.

[PostgreSQL]: https://www.postgresql.org/
[WebAuthn]: https://en.wikipedia.org/wiki/WebAuthn
[U2F Token]: https://en.wikipedia.org/wiki/Universal_2nd_Factor
[Yubico]: https://www.yubico.com/
[Chrome]: https://www.google.com/chrome/

![Verify your identity](https://i.imgur.com/1KXVbTb.png)
![Touch ID](https://i.imgur.com/KPF6vEg.png)

<h2 id="dependencies">2. Dependencies</h2>

[pgcrypto] for the [digest()] and [gen_random_bytes()] functions.

[pguecc] for the ECDSA cryptographic [ecdsa_verify()] function.

[pgcrypto]: https://www.postgresql.org/docs/current/pgcrypto.html
[digest()]: https://www.postgresql.org/docs/current/pgcrypto.html#id-1.11.7.34.6
[gen_random_bytes()]: https://www.postgresql.org/docs/current/pgcrypto.html#id-1.11.7.34.10
[pguecc]: https://github.com/ameensol/pg-ecdsa
[ecdsa_verify()]: https://github.com/ameensol/pg-ecdsa#ecdsa_verifypublic_key-textbytea-input_data-bytea-signature-textbytea-hash_func-text-curve_name-text

<h2 id="installation">3. Installation</h2>

Install the `webauthn` extension with:

    $ git clone https://github.com/truthly/pg-webauthn.git
    $ cd pg-webauthn
    $ make
    $ make install
    $ make installcheck

Note that the Postgres development tools and a C compiler must be installed
(the postgresql-dev or similar package) and the [pgcrypto] extension must
be included in the Postgres distribution (it's generally included by default;
if not, the error will mention "could not open extension control file
".../pgcrypto.control").

<h2 id="usage">4. Usage</h2>

Use with:

    $ psql
    # CREATE EXTENSION webauthn CASCADE;
    NOTICE:  installing required extension "pguecc"
    NOTICE:  installing required extension "pgcrypto"
    CREATE EXTENSION;

<h2 id="public-api">5. Public API</h2>

The public API consists of two sign-up functions and two sign-in functions.

<h3 id="sign-up">5.1. Sign-up functions</h3>

To sign-up, the browser first calls [webauthn.init_credential()] to get a list of supported crypto algorithms together with a random challenge to be used in the subsequent [webauthn.make_credential()] call to save the public key credential generated by the browser.

<h3 id="init-credential">webauthn.init_credential(...) → jsonb</h3>

Input Parameter                | Type                                     | Default
------------------------------ | ---------------------------------------- | -------
[challenge]                    | bytea                                    |
[relying_party_name]           | text                                     |
[relying_party_id]             | text                                     |
[user_name]                    | text                                     |
[user_id]                      | bytea                                    |
[user_display_name]            | text                                     |
[timeout]                      | interval                                 |
[user_verification]            | [webauthn.user_verification_requirement] | 'preferred'
[tx_auth_simple]               | text                                     | `NULL`
[tx_auth_generic_content_type] | text                                     | `NULL`
[tx_auth_generic_content]      | bytea                                    | `NULL`

[challenge]: https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge
[relying_party_name]: https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params
[relying_party_id]: https://www.w3.org/TR/webauthn-2/#relying-party-identifier
[user_name]: https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user
[user_id]: https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user
[user_display_name]: https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user
[timeout]: https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout
[user_verification]: https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification
[tx_auth_simple]: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions
[tx_auth_generic_content_type]: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions
[tx_auth_generic_content]: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions/extensions
[webauthn.user_verification_requirement]: https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement

Source code: [FUNCTIONS/init_credential.sql](https://github.com/truthly/pg-webauthn/blob/master/FUNCTIONS/init_credential.sql#L1)

Stores the random challenge and all the other fields to the [webauthn.credential_challenges](https://github.com/truthly/pg-webauthn/blob/master/TABLES/credential_challenges.sql) table.
Returns a json object compatible with the browser [navigator.credentials.create()] method,
where the only key, `publicKey`, contains a [PublicKeyCredentialCreationOptions](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions) object.

[navigator.credentials.create()]: https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create

```sql
SELECT jsonb_pretty(webauthn.init_credential(
  challenge := '\xf1f49abe5e3dcff7a1f522252f4fb574df415dd087aae156114ac9b51fbf4129'::bytea,
  relying_party_name := 'Localhost'::text,
  relying_party_id := 'localhost'::text,
  user_name := 'test'::text,
  user_id := '\xb3368c7317791c5a98b81428cdf3e35012aa71e6090d04930b390049ead7c282064ee24e9dc7219b6d727cc85aad4dcc0f3134f8e62c6c896a48ac08aac3db1b'::bytea,
  user_display_name := 'test'::text,
  timeout := '2 minutes'::interval
));
```

```json
{
    "publicKey": {
        "rp": {
            "id": "localhost",
            "name": "Localhost"
        },
        "user": {
            "id": "szaMcxd5HFqYuBQozfPjUBKqceYJDQSTCzkASerXwoIGTuJOncchm21yfMharU3MDzE0-OYsbIlqSKwIqsPbGw",
            "name": "test",
            "displayName": "test"
        },
        "timeout": 120000,
        "challenge": "8fSavl49z_eh9SIlL0-1dN9BXdCHquFWEUrJtR-_QSk",
        "attestation": "none",
        "pubKeyCredParams": [
            {
                "alg": -7,
                "type": "public-key"
            }
        ],
        "authenticatorSelection": {
            "userVerification": "preferred",
            "requireResidentKey": false
        }
    }
}
```

<h3 id="make-credential"><code>webauthn.make_credential(...) → user_id bytea</code></h3>

Input Parameter      | Type
-------------------- | ------------------------
[credential_id]      | text (*[base64url]*)
[credential_type]    | [webauthn.credential_type]
[attestation_object] | text (*[base64url]*)
[client_data_json]   | text (*[base64url]*)
[relying_party_id]   | text (*[valid domain string]*)

[credential_id]: https://www.w3.org/TR/webauthn-2/#credential-id
[credential_type]: https://www.w3.org/TR/webauthn-2/#enum-credentialType
[webauthn.credential_type]: https://www.w3.org/TR/webauthn-2/#enum-credentialType
[attestation_object]: https://www.w3.org/TR/webauthn-2/#attestation-object
[client_data_json]: https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson
[relying_party_id]: https://www.w3.org/TR/webauthn-2/#relying-party-identifier
[base64url]: https://tools.ietf.org/html/rfc4648#section-5
[valid domain string]: https://url.spec.whatwg.org/#valid-domain-string

Source code: [FUNCTIONS/make_credential.sql](https://github.com/truthly/pg-webauthn/blob/master/FUNCTIONS/make_credential.sql#L1)

Stores the public key for the credential generated by the browser to the [webauthn.credentials](https://github.com/truthly/pg-webauthn/blob/master/TABLES/credentials.sql) table.
The `challenge` can only be used once to prevent replay attacks.
If successful, returns the corresponding `user_id` bytea value given as input to [webauthn.init_credential()], or `NULL` to indicate failure.

```sql
SELECT * FROM webauthn.make_credential(
  credential_id := 'ASiVjgqKJgvSawjRv_bjFR6l9uOgpLJ9jaZbGkxytC3vQzq21tlSuPgAnvQF6B0BLK0dujjrqvK3oBktYP8FEdYOZz8LK8PjiyDGXiCrlSYDy58JILDNJIi-n7973HgHhYiDgN_iBCTfX9Y',
  credential_type := 'public-key',
  attestation_object := 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjvSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFX9SYD63OAAI1vMYKZIsLJfHwVQMAawEolY4KiiYL0msI0b_24xUepfbjoKSyfY2mWxpMcrQt70M6ttbZUrj4AJ70BegdASytHbo466ryt6AZLWD_BRHWDmc_CyvD44sgxl4gq5UmA8ufCSCwzSSIvp-_e9x4B4WIg4Df4gQk31_WpQECAyYgASFYIFYGLzqrkNKDty3WMhTXQzjWxIXZekODNhjBB8MjZHgpIlgg1wRbPHszTjstSPn7dPAqVDmO0krRy8rWpTjJDAeOFVY',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOGZTYXZsNDl6X2VoOVNJbEwwLTFkTjlCWGRDSHF1RldFVXJKdFItX1FTayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  relying_party_id := 'localhost'
);
                                                              user_id                                                               
------------------------------------------------------------------------------------------------------------------------------------
 \xb3368c7317791c5a98b81428cdf3e35012aa71e6090d04930b390049ead7c282064ee24e9dc7219b6d727cc85aad4dcc0f3134f8e62c6c896a48ac08aac3db1b
(1 row)
```

<h3 id="sign-in">5.2. Sign-in functions</h3>

To sign-in, the browser first calls [webauthn.get_credentials()] to get a list of allowed credentials for the given [user_name] together with a random challenge to be used in the subsequent [webauthn.verify_assertion()] call to verify the signature generated by the browser.

<h3 id="get-credentials"><code>webauthn.get_credentials(...) → jsonb</code></h3>

Input Parameter                | Type                                     | Default
------------------------------ | ---------------------------------------- | -------
[challenge]                    | bytea                                    |
[relying_party_id]             | text (*[valid domain string]*)           |
[user_name]                    | text                                     |
[timeout](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout) | interval |
[user_verification]            | [webauthn.user_verification_requirement] | 'preferred'
[tx_auth_simple]               | text                                     | `NULL`
[tx_auth_generic_content_type] | text                                     | `NULL`
[tx_auth_generic_content]      | bytea                                    | `NULL`

Source code: [FUNCTIONS/get_credentials.sql](https://github.com/truthly/pg-webauthn/blob/master/FUNCTIONS/get_credentials.sql#L1)

Stores the random challenge to the [webauthn.assertion_challenges](https://github.com/truthly/pg-webauthn/blob/master/TABLES/assertion_challenges.sql) table
and returns a json object with all public keys matching [relying_party_id] and [user_name].
Such public keys have previously been created by the [webauthn.make_credential()] function,
stored in the [webauthn.credentials](https://github.com/truthly/pg-webauthn/blob/master/TABLES/credentials.sql) table.

The returned json object is compatible with the browser [navigator.credentials.get()] method,
where the only key, `publicKey`, contains a [PublicKeyCredentialRequestOptions](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions) object.

[navigator.credentials.get()]: https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get

```sql
SELECT jsonb_pretty(webauthn.get_credentials(
  challenge := '\xa5174d506a1c0a0e9cd9cd65dae1221582b17824cb9b8c91f032f43c1c09cd1f'::bytea,
  relying_party_id := 'localhost',
  user_name := 'test',
  timeout := '2 minutes'::interval
));
```

```json
{
    "publicKey": {
        "rpId": "localhost",
        "timeout": 120000,
        "challenge": "pRdNUGocCg6c2c1l2uEiFYKxeCTLm4yR8DL0PBwJzR8",
        "allowCredentials": [
            {
                "id": "ASiVjgqKJgvSawjRv_bjFR6l9uOgpLJ9jaZbGkxytC3vQzq21tlSuPgAnvQF6B0BLK0dujjrqvK3oBktYP8FEdYOZz8LK8PjiyDGXiCrlSYDy58JILDNJIi-n7973HgHhYiDgN_iBCTfX9Y",
                "type": "public-key"
            }
        ],
        "userVerification": "preferred"
    }
}
```

<h3 id="verify-assertion"><code>webauthn.verify_assertion(...) → bigint</code></h3>

Input Parameter      | Type
-------------------- | --------------------------
[credential_id]      | text (*[base64url]*)
[credential_type]    | [webauthn.credential_type]
[authenticator_data] | text (*[base64url]*)
[client_data_json]   | text (*[base64url]*)
[signature]          | text (*[base64url]*)
[user_handle]        | text (*[base64url]*)
[relying_party_id]   | text (*[valid domain string]*)

[authenticator_data]: https://www.w3.org/TR/webauthn-2/#authenticator-data
[signature]: https://www.w3.org/TR/webauthn-2/#assertion-signature
[user_handle]: https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle

Source code: [FUNCTIONS/verify_assertion.sql](https://github.com/truthly/pg-webauthn/blob/master/FUNCTIONS/verify_assertion.sql#L1)

Verifies the [signature] is valid for the credential matching [credential_id], [credential_type], [client_data_json]->>[challenge] and [relying_party_id].

The [user_handle] must also match the [user_id] for the credential, but not if it is `NULL` or empty string, in which case the check is skipped.

The [challenge] can only be used once to prevent replay attacks.

If the [signature] could be successfully verified, the function stores the verified assertion to the [webauthn.assertions](https://github.com/truthly/pg-webauthn/blob/master/TABLES/assertions.sql) table and returns the `user_id` bytea value for the corresponding credential, or `NULL` to indicate failure.


```sql
SELECT * FROM webauthn.verify_assertion(
  credential_id := 'ASiVjgqKJgvSawjRv_bjFR6l9uOgpLJ9jaZbGkxytC3vQzq21tlSuPgAnvQF6B0BLK0dujjrqvK3oBktYP8FEdYOZz8LK8PjiyDGXiCrlSYDy58JILDNJIi-n7973HgHhYiDgN_iBCTfX9Y',
  credential_type := 'public-key',
  authenticator_data := 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFX9SYFg',
  client_data_json := 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicFJkTlVHb2NDZzZjMmMxbDJ1RWlGWUt4ZUNUTG00eVI4REwwUEJ3SnpSOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  signature := 'MEUCIBLCsANiAuhOPX2_GkzCPHhYPAL2xL1Ms22xFHiLDHJfAiEA_Ru_HfC51p-PjvU9VVV5lRKk_swZ9vKMJedQyhnsc4w',
  user_handle := 'szaMcxd5HFqYuBQozfPjUBKqceYJDQSTCzkASerXwoIGTuJOncchm21yfMharU3MDzE0-OYsbIlqSKwIqsPbGw',
  relying_party_id := 'localhost'
);
                                                              user_id                                                               
------------------------------------------------------------------------------------------------------------------------------------
 \xb3368c7317791c5a98b81428cdf3e35012aa71e6090d04930b390049ead7c282064ee24e9dc7219b6d727cc85aad4dcc0f3134f8e62c6c896a48ac08aac3db1b
(1 row)
```
