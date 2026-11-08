//! XML decryption as `xml-encryption` 3 does it for Node-SAML (`decrypt(xml, { key })`): the content key from the
//! first `EncryptedKey` (RSA-OAEP with MGF1, its digest from `DigestMethod`, or RSA PKCS #1 v1.5), then AES-CBC
//! (128/256), AES-GCM (128/256) or Triple DES over the `CipherValue`. Insecure algorithms are allowed, as Node-SAML
//! leaves `disallowDecryptionWithInsecureAlgorithm` off.

use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use rsa::{Oaep, Pkcs1v15Encrypt};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::c14n::DSIG_NS;
use crate::keys::{SamlError, SamlResult, base64_decode, private_key};
use crate::xml::{Document, NodeId};

const RSA_OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
const AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const TRIPLEDES_CBC: &str = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

fn plain(message: impl Into<String>) -> SamlError {
    SamlError::plain(message)
}

/// The elements of the decrypted subtree (`//*` of the re-parsed `encryptedAssertion.toString()`).
fn all_elements(document: &Document, root: NodeId) -> Vec<NodeId> {
    document
        .self_and_descendants(root)
        .into_iter()
        .filter(|node| document.element(*node).is_some())
        .collect()
}

/// `//*[local-name()=a]/*[local-name()=b]/...`: the elements reached by a path of local names, in document order.
fn path(document: &Document, root: NodeId, names: &[&str]) -> Vec<NodeId> {
    let mut current: Vec<NodeId> = all_elements(document, root)
        .into_iter()
        .filter(|node| document.is(*node, None, names[0]))
        .collect();
    for name in &names[1..] {
        let mut next = Vec::new();
        for node in current {
            next.extend(document.find_children(node, None, name));
        }
        current = next;
    }
    let order = document.self_and_descendants(root);
    current.sort_by_key(|node| order.iter().position(|item| item == node));
    current.dedup();
    current
}

/// `decryptKeyInfo(doc, { key })`.
fn decrypt_key(document: &Document, root: NodeId, key: &str) -> SamlResult<Vec<u8>> {
    let key_info = all_elements(document, root)
        .into_iter()
        .find(|node| document.is(*node, Some(DSIG_NS), "KeyInfo"))
        .or_else(|| {
            path(document, root, &["EncryptedData", "KeyInfo"])
                .first()
                .copied()
        });
    let mut retrieval_uri: Option<String> = None;
    let mut method = path(
        document,
        root,
        &["KeyInfo", "EncryptedKey", "EncryptionMethod"],
    )
    .first()
    .copied();
    if method.is_none() {
        let retrieval = path(
            document,
            root,
            &["EncryptedData", "KeyInfo", "RetrievalMethod"],
        )
        .first()
        .copied();
        retrieval_uri = retrieval
            .and_then(|node| document.attr(node, "URI"))
            .filter(|uri| !uri.is_empty())
            .map(str::to_owned);
        if let Some(uri) = &retrieval_uri {
            let id: String = uri.chars().skip(1).collect();
            method = all_elements(document, root)
                .into_iter()
                .filter(|node| {
                    document.is(*node, None, "EncryptedKey")
                        && document.attr(*node, "Id") == Some(id.as_str())
                })
                .flat_map(|node| document.find_children(node, None, "EncryptionMethod"))
                .next();
        }
    }
    let Some(method) = method else {
        return Err(plain("cant find encryption algorithm"));
    };
    let mut oaep_hash = "sha1";
    if let Some(digest) = path(
        document,
        root,
        &[
            "KeyInfo",
            "EncryptedKey",
            "EncryptionMethod",
            "DigestMethod",
        ],
    )
    .first()
    {
        match document.attr(*digest, "Algorithm") {
            Some("http://www.w3.org/2000/09/xmldsig#sha256") => oaep_hash = "sha256",
            Some("http://www.w3.org/2000/09/xmldsig#sha512") => oaep_hash = "sha512",
            _ => {}
        }
    }
    let algorithm = document
        .attr(method, "Algorithm")
        .unwrap_or_default()
        .to_owned();
    let cipher_value = match &retrieval_uri {
        Some(uri) => {
            let id: String = uri.chars().skip(1).collect();
            all_elements(document, root)
                .into_iter()
                .filter(|node| {
                    document.is(*node, None, "EncryptedKey")
                        && document.attr(*node, "Id") == Some(id.as_str())
                })
                .flat_map(|node| document.find_children(node, None, "CipherData"))
                .flat_map(|node| document.find_children(node, None, "CipherValue"))
                .next()
        }
        None => {
            if key_info.is_none() {
                return Err(plain(
                    "Cannot read properties of undefined (reading 'nodeType')",
                ));
            }
            all_elements(document, root)
                .into_iter()
                .find(|node| document.is(*node, None, "CipherValue"))
        }
    };
    let Some(cipher_value) = cipher_value else {
        return Err(plain(
            "Cannot read properties of undefined (reading 'textContent')",
        ));
    };
    let encrypted = base64_decode(&document.text_content(cipher_value));
    let key = private_key(key)?;
    let failed = |error: rsa::Error| plain(error.to_string());
    match algorithm.as_str() {
        RSA_OAEP_MGF1P => match oaep_hash {
            "sha256" => key
                .decrypt(Oaep::new::<Sha256>(), &encrypted)
                .map_err(failed),
            "sha512" => key
                .decrypt(Oaep::new::<Sha512>(), &encrypted)
                .map_err(failed),
            _ => key.decrypt(Oaep::new::<Sha1>(), &encrypted).map_err(failed),
        },
        RSA_1_5 => key.decrypt(Pkcs1v15Encrypt, &encrypted).map_err(failed),
        other => Err(plain(format!(
            "key encryption algorithm {other} not supported"
        ))),
    }
}

/// `decryptWithAlgorithm` for the CBC modes: no automatic padding check, then the last byte's padding stripped.
fn cbc_decrypt<D>(key: &[u8], iv_length: usize, content: &[u8]) -> SamlResult<Vec<u8>>
where
    D: BlockDecryptMut + KeyIvInit,
{
    if content.len() < iv_length {
        return Err(plain("Invalid initialization vector"));
    }
    let (iv, body) = content.split_at(iv_length);
    let decryptor = D::new_from_slices(key, iv).map_err(|_| plain("Invalid key length"))?;
    let mut buffer = body.to_vec();
    let decrypted = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| plain("error:1C80006B:Provider routines::wrong final block length"))?
        .to_vec();
    let Some(&padding) = decrypted.last() else {
        return Err(plain("callback is not defined"));
    };
    if padding >= 1 && (padding as usize) <= iv_length && decrypted.len() >= padding as usize {
        Ok(decrypted[..decrypted.len() - padding as usize].to_vec())
    } else {
        Err(plain("callback is not defined"))
    }
}

fn gcm_decrypt<C>(key: &[u8], content: &[u8]) -> SamlResult<Vec<u8>>
where
    C: Aead + KeyInit,
{
    let cipher = C::new_from_slice(key).map_err(|_| plain("Invalid key length"))?;
    if content.len() < 12 + 16 {
        return Err(plain("Unsupported state or unable to authenticate data"));
    }
    let (iv, rest) = content.split_at(12);
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: rest,
                aad: &[],
            },
        )
        .map_err(|_| plain("Unsupported state or unable to authenticate data"))
}

/// `xmlenc.decrypt(element.toString(), { key })`: the decrypted XML text of an `EncryptedAssertion` (or
/// `EncryptedData`) subtree.
pub fn decrypt(document: &Document, root: NodeId, key: &str) -> SamlResult<String> {
    let symmetric = decrypt_key(document, root, key)?;
    let Some(method) = path(document, root, &["EncryptedData", "EncryptionMethod"])
        .first()
        .copied()
    else {
        return Err(plain(
            "Cannot read properties of undefined (reading 'getAttribute')",
        ));
    };
    let algorithm = document
        .attr(method, "Algorithm")
        .unwrap_or_default()
        .to_owned();
    let Some(value) = path(
        document,
        root,
        &["EncryptedData", "CipherData", "CipherValue"],
    )
    .first()
    .copied() else {
        return Err(plain(
            "Cannot read properties of undefined (reading 'textContent')",
        ));
    };
    let encrypted = base64_decode(&document.text_content(value));
    let decrypted = match algorithm.as_str() {
        AES128_CBC => cbc_decrypt::<cbc::Decryptor<Aes128>>(&symmetric, 16, &encrypted)?,
        AES256_CBC => cbc_decrypt::<cbc::Decryptor<Aes256>>(&symmetric, 16, &encrypted)?,
        TRIPLEDES_CBC => cbc_decrypt::<cbc::Decryptor<des::TdesEde3>>(&symmetric, 8, &encrypted)?,
        AES128_GCM => gcm_decrypt::<Aes128Gcm>(&symmetric, &encrypted)?,
        AES256_GCM => gcm_decrypt::<Aes256Gcm>(&symmetric, &encrypted)?,
        other => return Err(plain(format!("encryption algorithm {other} not supported"))),
    };
    Ok(String::from_utf8_lossy(&decrypted).into_owned())
}
