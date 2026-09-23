import { X509Certificate } from 'node:crypto';
import { DOMParser } from '@xmldom/xmldom';
import { IamError } from '@better-iam/core';

const METADATA_NS = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const REDIRECT_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

/** What a service provider needs from an identity provider's SAML metadata. */
export interface IdpMetadata {
  entityId: string;
  /** The HTTP-Redirect single sign-on endpoint. */
  entryPoint: string;
  /** PEM signing certificates, in document order (several during certificate rollover). */
  certificates: string[];
  /** The HTTP-Redirect single logout endpoint, when published. */
  singleLogoutUrl?: string;
}

/** Details administrators need to watch certificate rollover. */
export interface CertificateInfo {
  fingerprint256: string;
  subject: string;
  notBefore: string;
  notAfter: string;
  expired: boolean;
}

/** Normalizes a PEM or bare base64 DER certificate to PEM, rejecting anything that is not a parseable X.509 certificate. */
export function normalizeCertificate(value: string): string {
  const body = String(value)
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  if (!body || body.length > 16_384 || !/^[A-Za-z0-9+/]+=*$/.test(body))
    throw new IamError('INVALID_INPUT', 'IdP certificates must be X.509 certificates.');
  const pem = `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----`;
  try {
    new X509Certificate(pem);
  } catch {
    throw new IamError('INVALID_INPUT', 'IdP certificates must be X.509 certificates.');
  }
  return pem;
}

export function certificateInfo(pem: string): CertificateInfo {
  const certificate = new X509Certificate(pem);
  return {
    fingerprint256: certificate.fingerprint256,
    subject: certificate.subject,
    notBefore: new Date(certificate.validFrom).toISOString(),
    notAfter: new Date(certificate.validTo).toISOString(),
    expired: new Date(certificate.validTo).getTime() <= Date.now(),
  };
}

/**
 * Reads entity ID, redirect-binding SSO/SLO endpoints, and signing certificates from IdP metadata. The document must
 * describe exactly one identity provider; DTDs and entities are refused. Metadata signatures are not checked: import
 * metadata only from a source you trust (an administrator upload or an HTTPS URL of the IdP).
 */
export function parseIdpMetadata(xml: string): IdpMetadata {
  if (typeof xml !== 'string' || xml.length > 512 * 1024 || /<!DOCTYPE|<!ENTITY/i.test(xml))
    throw new IamError('INVALID_INPUT', 'Unsafe or oversized SAML metadata.');
  const problems: string[] = [];
  const document = new DOMParser({
    errorHandler: {
      warning: () => undefined,
      error: (message) => problems.push(message),
      fatalError: (message) => problems.push(message),
    },
  }).parseFromString(xml, 'text/xml');
  const descriptors = document.getElementsByTagNameNS(METADATA_NS, 'IDPSSODescriptor');
  if (problems.length || descriptors.length !== 1)
    throw new IamError('INVALID_INPUT', 'Metadata must describe exactly one identity provider.');
  const idp = descriptors.item(0)!;
  const entity = idp.parentNode as unknown as {
    localName?: string;
    namespaceURI?: string;
    getAttribute(name: string): string | null;
  };
  const entityId =
    entity?.localName === 'EntityDescriptor' && entity.namespaceURI === METADATA_NS
      ? entity.getAttribute('entityID')
      : null;
  if (!entityId) throw new IamError('INVALID_INPUT', 'The identity provider has no entityID.');
  const endpoint = (name: string) => {
    const services = idp.getElementsByTagNameNS(METADATA_NS, name);
    for (let i = 0; i < services.length; i++) {
      const service = services.item(i)!;
      if (service.getAttribute('Binding') === REDIRECT_BINDING)
        return service.getAttribute('Location') ?? undefined;
    }
    return undefined;
  };
  const entryPoint = endpoint('SingleSignOnService');
  if (!entryPoint)
    throw new IamError(
      'INVALID_INPUT',
      'The identity provider has no HTTP-Redirect sign-on endpoint.',
    );
  const certificates: string[] = [];
  const keys = idp.getElementsByTagNameNS(METADATA_NS, 'KeyDescriptor');
  for (let i = 0; i < keys.length; i++) {
    const key = keys.item(i)!;
    const use = key.getAttribute('use');
    if (use && use !== 'signing') continue;
    const certs = key.getElementsByTagNameNS(DSIG_NS, 'X509Certificate');
    for (let j = 0; j < certs.length; j++) {
      const pem = normalizeCertificate(certs.item(j)!.textContent ?? '');
      if (!certificates.includes(pem)) certificates.push(pem);
    }
  }
  if (!certificates.length)
    throw new IamError('INVALID_INPUT', 'The identity provider publishes no signing certificate.');
  const singleLogoutUrl = endpoint('SingleLogoutService');
  return { entityId, entryPoint, certificates, ...(singleLogoutUrl ? { singleLogoutUrl } : {}) };
}
