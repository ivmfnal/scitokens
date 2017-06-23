
SciTokens Library
=================

This library aims to be a reference implementation of the SciTokens' JSON Web Token (JWT) token format.

SciTokens is built on top of the [PyJWT](https://github.com/jpadilla/pyjwt) and [cryptography](https://cryptography.io/en/latest/) libraries.  We aim to provide a safe, high-level interface for token manipulation, avoiding common pitfalls of using the underling libraries directly.

*NOTE*: SciTokens (the format and this library) is currently being designed; this README describes how we would like it to work, not necessarily current functionality.

Generating Tokens
-----------------

Usage revolves around the `SciToken` object.  This can be generated directly:

```
>>> import scitokens
>>> token = scitokens.SciToken() # Create token and generate a new private key
>>> token2 = scitokens.SciToken(key=private_key) # Create token using existing key
```

where `key` is a private key object (more later on generating private keys).  Direct generation using a private key will most often be done to do a _base token_.  SciTokens can be chained, meaning one token can be appended to another:

```
>>> token = scitokens.SciToken(parent=parent_token)
```

The generated object, `token`, will default to having all the authoriations of the parent token - but is mutable and can add further restrictions.

Tokens contain zero or more claims, which are facts about the token that typically indicate some sort of authorization the bearer of the token has.  A token has a list of key-value pairs; each token can only have a single value per key, but multiple values per key can occur in a token chain.

To set a claim, one can use dictionary-like setter:

```
>>> token['claim1'] = 'value2'
```

The value of each claim should be a Python object that can be serialized to JSON.

Token Serialization
-------------------

Parent tokens are typically generated by a separate server and sent as a response to a successful authentication or authorization request.  SciTokens are built on top of JSON Web Tokens (JWT), which define a useful base64-encoded serialization format.  A serialized token may look something like this:

```
eyJhbGciOiJFUzI1NiIsImN3ayI6eyJ5IjoiazRlM1FFeDVjdGJsWmNrVkhINlkzSFZoTzFadUxVVWNZQW5ON0xkREV3YyIsIngiOiI4TkU2ZEE2T1g4NHBybHZEaDZUX3kwcWJOYmc5a2xWc2pYQnJnSkw5aElBIiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyJ9LCJ0eXAiOiJKV1QiLCJ4NXUiOiJodHRwczovL3ZvLmV4YW1wbGUuY29tL0pXUyJ9.eyJyZWFkIjoiL2xpZ28ifQ.uXVzbcOBCK4S4W89HzlWNmnE9ZcpuRHKTrTXYv8LZL9cDy3Injf97xNPm756fKcYwBO5KykYngFrUSGa4owglA.eyJjcnYiOiAiUC0yNTYiLCAia3R5IjogIkVDIiwgImQiOiAieWVUTTdsVXk5bGJEX2hnLVVjaGp0aXZFWHZxSWxoelJQVEVaZDBaNFBpOCJ9
```

This is actually 4 separate base64-encoded strings, separated by the `.` character.  The four pieces are:

* A *header*, implementing the JSON Web Key standard, specifying the cryptographic properties of the token.
* A *payload*, specifying the claims (key-value pairs) encoded by the token and asserted by the VO.
* A *signature* of the header and payload, ensuring authenticity of the payload.
* A *key*, utilized to sign any derived tokens.  The key is an optional part of the token format, but may be required by some remote services.

Given a serialized token, the `scitokens` library can deserialize it:

```
>>> token = scitokens.SciToken.deserialize(token_serialized_bytes)
```

As part of the deserialization, the `scitokens` library will throw an exception if token verification failed.

The existing token can be serialized with the `serialize` method:

```
>>> token_serialized_bytes = token.serialize()
```

Validating Tokens
---------------

In SciTokens, we try to distinguish between _validating_ and _verifying_ tokings.  Here, verification refers to determining the integrity and authenticity of the token: can we validate the token came from a known source without tampering?  Can we validate the chain of trust?  Validation is determining whether the claims of the token are satisfied in a given context.

For example, if a token contains the claims `{vo: ligo, op: read, path: /ligo}`, we would first verify that the token is correctly signed by a known public key associated with LIGO.  When presented to a storage system along with an HTTP request, the storage system would validate the token authorizes the corresponding request (is it a GET request?  Is it for a sub-path of /ligo?).

Within the `scitokens` module, validation is done by the `Validator` object:

```
>>> val = scitokens.Validator()
```

This object can be reused for multiple validations.  All SciToken claims must be validated.  There are no "optional" claim attributes or values.

To validate a specific claim, provide a callback function to the `Validator` object:

```
>>> def validate_op(value):
...     return value == True
>>> val.add_validator("op", validate_op)
```

Once all the known validator callbacks have been registered, use the `validate` method with a token:

```
>>> val.validate(token)
```

This will throw a `ValidationException` if the token could not be validated.

