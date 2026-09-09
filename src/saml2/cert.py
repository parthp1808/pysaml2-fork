__author__ = "haho0032"

import base64
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from os import remove
from os.path import join
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.x509.oid import NameOID
import dateutil.parser

import saml2.cryptography.pki


class WrongInput(Exception):
    pass


class CertificateError(Exception):
    pass


class PayloadError(Exception):
    pass


_HASH_ALGORITHMS = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "md5": hashes.MD5,
}


def _get_hash_algorithm(hash_alg):
    if hash_alg is None:
        return hashes.SHA256()
    if isinstance(hash_alg, hashes.HashAlgorithm):
        return hash_alg
    alg_name = str(hash_alg).lower()
    hash_class = _HASH_ALGORITHMS.get(alg_name, hashes.SHA256)
    return hash_class()


def _to_serial_number(sn):
    if isinstance(sn, int):
        val = sn
    else:
        try:
            val = int(sn)
        except (ValueError, TypeError):
            try:
                val = uuid.UUID(str(sn)).int
            except (ValueError, TypeError):
                try:
                    val = int.from_bytes(str(sn).encode("utf-8"), "big")
                except Exception:
                    val = 1
    if val <= 0:
        val = abs(val) or 1
    if val >= (1 << 159):
        val = val % (1 << 159) or 1
    return val


class OpenSSLWrapper:
    def __init__(self):
        pass

    def create_certificate(
        self,
        cert_info,
        request=False,
        valid_from=0,
        valid_to=315360000,
        sn=1,
        key_length=1024,
        hash_alg="sha256",
        write_to_file=False,
        cert_dir="",
        cipher_passphrase=None,
    ):
        """
        Can create certificate requests, to be signed later by another
        certificate with the method
        create_cert_signed_certificate. If request is True.

        Can also create self signed root certificates if request is False.
        This is default behaviour.

        :param cert_info:         Contains information about the certificate.
                                  Is a dictionary that must contain the keys:
                                  cn                = Common name. This part
                                  must match the host being authenticated
                                  country_code      = Two letter description
                                  of the country.
                                  state             = State
                                  city              = City
                                  organization      = Organization, can be a
                                  company name.
                                  organization_unit = A unit at the
                                  organization, can be a department.
                                  Example:
                                                    cert_info_ca = {
                                                        "cn": "company.com",
                                                        "country_code": "se",
                                                        "state": "AC",
                                                        "city": "Dorotea",
                                                        "organization":
                                                        "Company",
                                                        "organization_unit":
                                                        "Sales"
                                                    }
        :param request:           True if this is a request for certificate,
                                  that should be signed.
                                  False if this is a self signed certificate,
                                  root certificate.
        :param valid_from:        When the certificate starts to be valid.
                                  Amount of seconds from when the
                                  certificate is generated.
        :param valid_to:          How long the certificate will be valid from
                                  when it is generated.
                                  The value is in seconds. Default is
                                  315360000 seconds, a.k.a 10 years.
        :param sn:                Serial number for the certificate. Default
                                  is 1.
        :param key_length:        Length of the key to be generated. Defaults
                                  to 1024.
        :param hash_alg:          Hash algorithm to use for the key. Default
                                  is sha256.
        :param write_to_file:     True if you want to write the certificate
                                  to a file. The method will then return
                                  a tuple with path to certificate file and
                                  path to key file.
                                  False if you want to get the result as
                                  strings. The method will then return a tuple
                                  with the certificate string and the key as
                                  string.
                                  WILL OVERWRITE ALL EXISTING FILES WITHOUT
                                  ASKING!
        :param cert_dir:          Where to save the files if write_to_file is
                                  true.
        :param cipher_passphrase  A dictionary with cipher and passphrase.
        Example::
                {"cipher": "blowfish", "passphrase": "qwerty"}

        :return:                  string representation of certificate,
                                  string representation of private key
                                  if write_to_file parameter is False otherwise
                                  path to certificate file, path to private
                                  key file
        """
        cn = cert_info["cn"]

        c_f = None
        k_f = None

        if write_to_file:
            cert_file = f"{cn}.crt"
            key_file = f"{cn}.key"
            try:
                remove(cert_file)
            except Exception:
                pass
            try:
                remove(key_file)
            except Exception:
                pass
            c_f = join(cert_dir, cert_file)
            k_f = join(cert_dir, key_file)

        if len(cert_info["country_code"]) != 2:
            raise WrongInput("Country code must be two letters!")

        try:
            k = _rsa.generate_private_key(public_exponent=65537, key_size=key_length)

            name_attributes = []
            if "country_code" in cert_info and cert_info["country_code"]:
                name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, cert_info["country_code"]))
            if "state" in cert_info and cert_info["state"]:
                name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_info["state"]))
            if "city" in cert_info and cert_info["city"]:
                name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, cert_info["city"]))
            if "organization" in cert_info and cert_info["organization"]:
                name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_info["organization"]))
            if "organization_unit" in cert_info and cert_info["organization_unit"]:
                name_attributes.append(
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, cert_info["organization_unit"])
                )
            if "cn" in cert_info and cert_info["cn"]:
                name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
            subject = x509.Name(name_attributes)

            hash_algorithm = _get_hash_algorithm(hash_alg)

            if request:
                csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(k, hash_algorithm)
                tmp_cert = csr.public_bytes(serialization.Encoding.PEM)
            else:
                now = datetime.now(timezone.utc)
                not_before = now + timedelta(seconds=valid_from)
                not_after = now + timedelta(seconds=valid_to)
                builder = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(subject)
                    .public_key(k.public_key())
                    .serial_number(_to_serial_number(sn))
                    .not_valid_before(not_before)
                    .not_valid_after(not_after)
                )
                cert = builder.sign(k, hash_algorithm)
                tmp_cert = cert.public_bytes(serialization.Encoding.PEM)

            if cipher_passphrase is not None:
                passphrase = cipher_passphrase["passphrase"]
                if isinstance(passphrase, str):
                    passphrase = passphrase.encode("utf-8")
                encryption_algorithm = serialization.BestAvailableEncryption(passphrase)
            else:
                encryption_algorithm = serialization.NoEncryption()

            tmp_key = k.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm,
            )

            if write_to_file:
                with open(c_f, "w") as fc:
                    fc.write(tmp_cert.decode("utf-8"))
                with open(k_f, "w") as fk:
                    fk.write(tmp_key.decode("utf-8"))
                return c_f, k_f
            return tmp_cert, tmp_key
        except Exception as ex:
            raise CertificateError("Certificate cannot be generated.", ex)

    def write_str_to_file(self, file, str_data):
        with open(file, "w") as f:
            f.write(str_data)

    def read_str_from_file(self, file, type="pem"):
        with open(file, "rb") as f:
            str_data = f.read()

        if type == "pem":
            return str_data

        if type in ["der", "cer", "crt"]:
            return base64.b64encode(str(str_data))

    def create_cert_signed_certificate(
        self,
        sign_cert_str,
        sign_key_str,
        request_cert_str,
        hash_alg="sha256",
        valid_from=0,
        valid_to=315360000,
        sn=1,
        passphrase=None,
    ):
        """
        Will sign a certificate request with a give certificate.
        :param sign_cert_str:     This certificate will be used to sign with.
                                  Must be a string representation of
                                  the certificate. If you only have a file
                                  use the method read_str_from_file to
                                  get a string representation.
        :param sign_key_str:        This is the key for the ca_cert_str
                                  represented as a string.
                                  If you only have a file use the method
                                  read_str_from_file to get a string
                                  representation.
        :param request_cert_str:  This is the prepared certificate to be
                                  signed. Must be a string representation of
                                  the requested certificate. If you only have
                                  a file use the method read_str_from_file
                                  to get a string representation.
        :param hash_alg:          Hash algorithm to use for the key. Default
                                  is sha256.
        :param valid_from:        When the certificate starts to be valid.
                                  Amount of seconds from when the
                                  certificate is generated.
        :param valid_to:          How long the certificate will be valid from
                                  when it is generated.
                                  The value is in seconds. Default is
                                  315360000 seconds, a.k.a 10 years.
        :param sn:                Serial number for the certificate. Default
                                  is 1.
        :param passphrase:        Password for the private key in sign_key_str.
        :return:                  String representation of the signed
                                  certificate.
        """
        sign_cert_bytes = sign_cert_str if isinstance(sign_cert_str, bytes) else sign_cert_str.encode("utf-8")
        sign_key_bytes = sign_key_str if isinstance(sign_key_str, bytes) else sign_key_str.encode("utf-8")
        request_cert_bytes = (
            request_cert_str if isinstance(request_cert_str, bytes) else request_cert_str.encode("utf-8")
        )

        if passphrase is not None and isinstance(passphrase, str):
            passphrase = passphrase.encode("utf-8")

        ca_cert = x509.load_pem_x509_certificate(sign_cert_bytes)
        ca_key = serialization.load_pem_private_key(sign_key_bytes, password=passphrase)
        req_cert = x509.load_pem_x509_csr(request_cert_bytes)

        now = datetime.now(timezone.utc)
        not_before = now + timedelta(seconds=valid_from)
        not_after = now + timedelta(seconds=valid_to)

        builder = (
            x509.CertificateBuilder()
            .subject_name(req_cert.subject)
            .issuer_name(ca_cert.subject)
            .public_key(req_cert.public_key())
            .serial_number(_to_serial_number(sn))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        cert = builder.sign(ca_key, _get_hash_algorithm(hash_alg))
        cert_dump = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return cert_dump

    def verify_chain(self, cert_chain_str_list, cert_str):
        """

        :param cert_chain_str_list: Must be a list of certificate strings,
        where the first certificate to be validate
        is in the beginning and the root certificate is last.
        :param cert_str: The certificate to be validated.
        :return:
        """
        for tmp_cert_str in cert_chain_str_list:
            valid, message = self.verify(tmp_cert_str, cert_str)
            if not valid:
                return False, message
            else:
                cert_str = tmp_cert_str
            return (True, "Signed certificate is valid and correctly signed by CA certificate.")

    def certificate_not_valid_yet(self, cert):
        if hasattr(cert, "not_valid_before_utc"):
            starts_to_be_valid = cert.not_valid_before_utc
        elif hasattr(cert, "not_valid_before"):
            starts_to_be_valid = cert.not_valid_before.replace(tzinfo=timezone.utc)
        elif hasattr(cert, "get_notBefore"):
            starts_to_be_valid = dateutil.parser.parse(cert.get_notBefore())
        else:
            raise TypeError("Unknown certificate object")
        if starts_to_be_valid.tzinfo is None:
            starts_to_be_valid = starts_to_be_valid.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if starts_to_be_valid < now:
            return False
        return True

    def _certificate_has_expired(self, cert):
        if hasattr(cert, "not_valid_after_utc"):
            expires = cert.not_valid_after_utc
        elif hasattr(cert, "not_valid_after"):
            expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
        elif hasattr(cert, "has_expired"):
            return cert.has_expired() == 1
        else:
            raise TypeError("Unknown certificate object")
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return now >= expires

    def verify(self, signing_cert_str, cert_str):
        """
        Verifies if a certificate is valid and signed by a given certificate.

        :param signing_cert_str: This certificate will be used to verify the
                                  signature. Must be a string representation
                                 of the certificate. If you only have a file
                                 use the method read_str_from_file to
                                 get a string representation.
        :param cert_str:         This certificate will be verified if it is
                                  correct. Must be a string representation
                                 of the certificate. If you only have a file
                                 use the method read_str_from_file to
                                 get a string representation.
        :return:                 Valid, Message
                                 Valid = True if the certificate is valid,
                                 otherwise false.
                                 Message = Why the validation failed.
        """
        try:
            cert_str_bytes = cert_str if isinstance(cert_str, bytes) else cert_str.encode("ascii")
            signing_cert_bytes = (
                signing_cert_str if isinstance(signing_cert_str, bytes) else signing_cert_str.encode("ascii")
            )

            ca_cert_crypto = saml2.cryptography.pki.load_pem_x509_certificate(signing_cert_bytes)
            cert_crypto = saml2.cryptography.pki.load_pem_x509_certificate(cert_str_bytes)

            if self.certificate_not_valid_yet(ca_cert_crypto):
                return False, "CA certificate is not valid yet."

            if self._certificate_has_expired(ca_cert_crypto):
                return False, "CA certificate is expired."

            if self._certificate_has_expired(cert_crypto):
                return False, "The signed certificate is expired."

            if self.certificate_not_valid_yet(cert_crypto):
                return False, "The signed certificate is not valid yet."

            def _get_cn(c):
                attrs = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                return attrs[0].value if attrs else None

            if _get_cn(ca_cert_crypto) == _get_cn(cert_crypto):
                return False, ("CN may not be equal for CA certificate and the signed certificate.")

            ca_public_key = ca_cert_crypto.public_key()

            try:
                if isinstance(ca_public_key, _rsa.RSAPublicKey):
                    ca_public_key.verify(
                        cert_crypto.signature,
                        cert_crypto.tbs_certificate_bytes,
                        _padding.PKCS1v15(),
                        cert_crypto.signature_hash_algorithm,
                    )
                elif isinstance(ca_public_key, _ec.EllipticCurvePublicKey):
                    ca_public_key.verify(
                        cert_crypto.signature,
                        cert_crypto.tbs_certificate_bytes,
                        _ec.ECDSA(cert_crypto.signature_hash_algorithm),
                    )
                else:
                    return False, f"Unsupported public key type: {type(ca_public_key)}"
                return True, "Signed certificate is valid and correctly signed by CA certificate."
            except Exception as e:
                return False, f"Certificate is incorrectly signed: {str(e)}"
        except Exception as e:
            return False, f"Certificate is not valid for an unknown reason. {str(e)}"


def read_cert_from_file(cert_file, cert_type="pem"):
    """Read a certificate from a file.

    If there are multiple certificates in the file, the first is returned.

    :param cert_file: The name of the file
    :param cert_type: The certificate type
    :return: A base64 encoded certificate as a string or the empty string
    """
    if not cert_file:
        return ""

    with open(cert_file, "rb") as fp:
        data = fp.read()

    try:
        cert = saml2.cryptography.pki.load_x509_certificate(data, cert_type)
        pem_data = saml2.cryptography.pki.get_public_bytes_from_cert(cert)
    except Exception as e:
        raise CertificateError(e)

    pem_data_no_headers = "".join(pem_data.splitlines()[1:-1])
    return pem_data_no_headers
