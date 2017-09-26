
"""
SciTokens reference library.

This library provides the primitives necessary for working with SciTokens
authorization tokens.
"""

import time

import jwt
from . import urltools

from .utils import keycache as KeyCache
from .utils.errors import MissingIssuerException, InvalidTokenFormat, MissingKeyException

class SciToken(object):
    """
    An object representing the contents of a SciToken.
    """

    def __init__(self, key=None, key_id=None, parent=None, claims=None):
        """
        Construct a SciToken object.
        
        :param key: Private key to sign the SciToken with.  It should be the PEM contents.
        :param str key_id: A string representing the Key ID that is used at the issuer
        :param parent: Parent SciToken that will be chained
        """
        
        if claims is not None:
            raise NotImplementedError()
    
        self._key = key
        self._key_id = key_id
        self._parent = parent
        self._claims = {}
        self._verified_claims = {}
        self.insecure = False
        self._serialized_token = None

    def claims(self):
        """
        Return an iterator of (key, value) pairs of claims, starting
        with the claims from the first token in the chain.
        """
        if self._parent:
            for claim, value in self._parent.claims():
                yield claim, value
        for claim, value in self._verified_claims.items():
            yield claim, value
        for claim, value in self._claims.items():
            yield claim, value


    def verify(self):
        """
        Verify the claims of the in-memory token.

        Automatically called by deserialize.
        """
        raise NotImplementedError()


    def serialize(self, include_key=False, issuer=None, lifetime=600):
        """
        Serialize the existing SciToken.
        
        :param bool include_key: When true, include the public key to the serialized token.  Default=False
        :param str issuer: A string indicating the issuer for the token.  It should be an HTTPS address,
                           as specified in https://tools.ietf.org/html/draft-ietf-oauth-discovery-07
        :param int lifetime: Number of seconds that the token should be valid
        :return str: base64 encoded token
        """
        
        if include_key is not False:
            raise NotImplementedError()
        
        if self._key == None:
            raise MissingKeyException("Unable to serialize, missing private key")
        
        # Issuer needs to be available, otherwise throw an error
        if issuer == None and 'iss' not in self._claims:
            raise MissingIssuerException("Issuer not specific in claims or as argument")
        
        if not issuer:
            issuer = self._claims['iss']
        
        # Set the issue and expiration time of the token
        issue_time = int(time.time())
        exp_time = int(issue_time + lifetime)
        
        # Add to validated and other claims
        payload = dict(self._verified_claims)
        payload.update(self._claims)

        
        # Anything below will override what is in the claims
        payload.update({
            "iss": issuer,
            "exp": exp_time,
            "iat": issue_time,
            "nbf": issue_time
        })
        
        if self._key_id != None:
            encoded = jwt.encode(payload, self._key, algorithm = "RS256", headers={'kid': self._key_id})
        else:
            encoded = jwt.encode(payload, self._key, algorithm = "RS256")
        self._serialized_token = encoded
        
        # Move claims over to verified claims
        self._verified_claims.update(self._claims)
        self._claims = {}
        
        return encoded
        
        

    def update_claims(self, claims):
        """
        Add new claims to the token.
        
        :param claims: Dictionary of claims to add to the token
        """
        
        self._claims.update(claims)

    def __setitem__(self, claim, value):
        """
        Assign a new claim to the token.
        """
        self._claims[claim] = value

    def __getitem__(self, claim):
        """
        Access the value corresponding to a particular claim; will
        return claims from both the verified and unverified claims.

        If a claim is not present, then a KeyError is thrown.
        """
        if claim in self._claims:
            return self._claims[claim]
        if claim in self._verified_claims:
            return self._verified_claims[claim]
        raise KeyError(claim)

    def get(self, claim, default=None, verified_only=False):
        """
        Return the value associated with a claim, returning the
        default if the claim is not present.  If `verified_only` is
        True, then a claim is returned only if it is in the verified claims
        """
        if verified_only:
            return self._verified_claims.get(claim, default)
        return self._claims.get(claim, self._verified_claims.get(claim, default))

    def clone_chain(self):
        """
        Return a new, empty SciToken
        """
        raise NotImplementedError()

    def _deserialize_key(self, key_serialized, unverified_headers):
        """
        Given a serialized key and a set of UNVERIFIED headers, return
        a corresponding private key object.
        """
        
        
    @staticmethod
    def deserialize(serialized_token, require_key=False, insecure=False):
        """
        Given a serialized SciToken, load it into a SciTokens object.

        Verifies the claims pass the current set of validation scripts.
        
        :param str serialized_token: The serialized token.
        :param bool require_key: When True, require the key
        :param bool insecure: When True, allow insecure methods to verify the issuer,
                              including allowing "localhost" issuer (useful in testing).  Default=False
        """
        
        if require_key is not False:
            raise NotImplementedError()

        if isinstance(serialized_token, bytes):
            serialized_token = serialized_token.decode('utf8')
        info = serialized_token.split(".")

        if len(info) != 3 and len(info) != 4: # header, format, signature[, key]
            raise InvalidTokenFormat("Serialized token is not a readable format.")

        if (len(info) != 4) and require_key:
            raise MissingKeyException("No key present in serialized token")

        serialized_jwt = info[0] + "." + info[1] + "." + info[2]

        unverified_headers = jwt.get_unverified_header(serialized_jwt)
        unverified_payload = jwt.decode(serialized_jwt, verify=False, algorithms=['RS256'])
        
        # Get the public key from the issuer
        keycache = KeyCache.KeyCache.getinstance()
        issuer_public_key = keycache.getkeyinfo(unverified_payload['iss'],
                            key_id=unverified_headers['kid'],
                            insecure=insecure)
        
        claims = jwt.decode(serialized_token, issuer_public_key, algorithms=['RS256'])
        # Do we have the private key?
        if len(info) == 4:
            to_return = SciToken(key = key)
        else:
            to_return = SciToken()
            
        to_return._verified_claims = claims
        to_return._serialized_token = serialized_token
        return to_return


class ValidationFailure(Exception):
    """
    Validation of a token was attempted but failed for an unknown reason.
    """


class NoRegisteredValidator(ValidationFailure):
    """
    The Validator object attempted validation of a token, but encountered a
    claim with no registered validator.
    """


class ClaimInvalid(ValidationFailure):
    """
    The Validator object attempted validation of a given claim, but one of the
    callbacks marked the claim as invalid.
    """


class MissingClaims(ValidationFailure):
    """
    Validation failed because one or more claim marked as critical is missing
    from the token.
    """


class Validator(object):

    """
    Validate the contents of a SciToken.

    Given a SciToken, validate the contents of its claims.  Unlike verification,
    which checks that the token is correctly signed, validation provides an easy-to-use
    interface that ensures the claims in the token are understood by the user.
    """


    def __init__(self):
        self._callbacks = {}

    def add_validator(self, claim, validate_op):
        """
        Add a validation callback for a given claim.  When the given ``claim``
        encountered in a token, ``validate_op`` object will be called with the
        following signature::

        >>> validate_op(value)

        where ``value`` is the value of the token's claim converted to a python
        object.

        The validator should return ``True`` if the value is acceptable and ``False``
        otherwise.
        """
        validator_list = self._callbacks.setdefault(claim, [])
        validator_list.append(validate_op)

    def validate(self, token, critical_claims=None):
        """
        Validate the claims of a token.

        This will iterate through all claims in the given :class:`SciToken`
        and determine whether all claims a valid, given the current set of
        validators.

        If ``critical_claims`` is specified, then validation will fail if one
        or more claim in this list is not present in the token.

        This will throw an exception if the token is invalid and return ``True``
        if the token is valid.
        """
        if critical_claims:
            critical_claims = set(critical_claims)
        else:
            critical_claims = set()
        for claim, value in token.claims():
            if claim in critical_claims:
                critical_claims.remove(claim)
            validator_list = self._callbacks.setdefault(claim, [])
            if not validator_list:
                raise NoRegisteredValidator("No validator was registered to handle encountered claim '%s'" % claim)
            for validator in validator_list:
                if not validator(value):
                    raise ClaimInvalid("Validator rejected value of '%s' for claim '%s'" % (value, claim))
        if len(critical_claims):
            raise MissingClaims("Validation failed because the following claims are missing: %s" % \
                                ", ".join(critical_claims))
        return True

    def __call__(self, token):
        return self.validate(token)


class EnforcementError(Exception):
    """
    A generic error during the enforcement of a SciToken.
    """

class Enforcer(object):

    """
    Enforce SciTokens-specific validation logic.

    Allows one to test if a given token has a particular authorization.

    This class is NOT thread safe; a separate object is needed for every thread.
    """

    _authz_requiring_path = set(["read", "write"])

    def __init__(self, issuer, site=None, audience=None):
        self._issuer = issuer
        self.last_failure = None
        if not self._issuer:
            raise EnforcementError("Issuer must be specified.")
        self._now = 0
        self._test_authz = None
        self._test_path = None
        self._audience = audience
        self._site = site
        self._validator = Validator()
        self._validator.add_validator("exp", self._validate_exp)
        self._validator.add_validator("nbf", self._validate_nbf)
        self._validator.add_validator("iss", self._validate_iss)
        self._validator.add_validator("iat", self._validate_iat)
        self._validator.add_validator("site", self._validate_site)
        self._validator.add_validator("aud", self._validate_aud)
        self._validator.add_validator("path", self._validate_path)
        self._validator.add_validator("authz", self._validate_authz)

    def add_validator(self, claim, validator):
        """
        Add a user-defined validator in addition to the default enforcer logic.
        """
        self._validator.add_validator(claim, validator)

    def test(self, token, authz, path=None):
        """
        Test whether a given token has the requested permission within the
        current enforcer context.
        """
        critical_claims = set(["authz"])
        if authz in self._authz_requiring_path:
            critical_claims.add("path")
        self._now = time.time()
        self._test_path = path
        self._test_authz = authz
        try:
            self._validator.validate(token, critical_claims=critical_claims)
        except ValidationFailure as vf:
            self.last_failure = str(vf)
            return False
        return True

    def _validate_exp(self, value):
        exp = float(value)
        return exp >= self._now

    def _validate_nbf(self, value):
        nbf = float(value)
        return nbf < self._now

    def _validate_iss(self, value):
        return self._issuer == value

    def _validate_iat(self, value):
        return float(value) < self._now

    def _validate_site(self, value):
        if not self._site:
            return False
        return value == self._site

    def _validate_aud(self, value):
        if not self._audience:
            return False
        return value == self._audience

    def _validate_path(self, value):
        if not isinstance(value, list):
            value = [value]
        norm_requested_path = urltools.normalize_path(self._test_path)
        for path in value:
            norm_path = urltools.normalize_path(path)
            if norm_requested_path.startswith(norm_path):
                return True
        return False

    def _validate_authz(self, value):
        if not isinstance(value, list):
            value = [value]
        for authz in value:
            if self._test_authz == authz:
                return True
        return False

