import { createHash, Hash, BinaryLike } from "crypto";

/**
 * Available choice of hash algorithms for disclosures.
 * 
 * > The hash algorithm identifier MUST be a hash algorithm
 * > value from the "Hash Name String" column in the IANA
 * > "Named Information Hash Algorithm" registry
 * > [IANA.Hash.Algorithms] or a value defined in another
 * > specification and/or profile of this specification.
 * 
 * Spec: {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.1.1}
 * IANA.Hash.Algorithms: {@link https://www.iana.org/assignments/named-information/named-information.xhtml}
 * 
 * See also 11.5. Choice of a Hash Algorithm for security considerations.
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-choice-of-a-hash-algorithm}
 */
export type SDHashAlg = "sha-256" | "sha-256-128" | "sha-256-120" | "sha-256-96" | "sha-256-64" | "sha-256-32" | "sha-384" | "sha-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2s-256" | "blake2b-256" | "blake2b-512" | "k12-256" | "k12-512";

/**
 * The default hashing algorithm for disclosures.
 *
 * > If the _sd_alg claim is not present at the top level, a default value of sha-256 MUST be used.
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-hash-function-claim}
 */
export const SDDefaultHashAlg: SDHashAlg = "sha-256";

// Hash data with the given algorithm.
// TODO: Users may want to give preferred hash algorithms.
export function hash(data: BinaryLike, hashAlg: SDHashAlg): Buffer {
    const hash: Hash = createHash(translateHashAlg(hashAlg));  // Note that you can't reuse the Hash instance.
    return hash.update(data).digest();
}

const prohibitedHashAlgorithms = ["MD2", "MD4", "MD5", "SHA-1"];
const weakHashAlgorithms = ["sha-256-32", "sha-256-64"];

export function requireSecondPreimageResistant(hashAlg: string) {
    if (prohibitedHashAlgorithms.includes(hashAlg)) {
        throw new Error("The hash algorithms MD2, MD4, MD5, and SHA-1 revealed fundamental weaknesses and MUST NOT be used.");
    }
    if (weakHashAlgorithms.includes(hashAlg)) {
        console.warn("A weak hash algorithm is used for disclosure digests.");
    }
}

/**
 * crypto.makeHash() requires hash names compatible with OpenSSL.
 *
 * > {@code openssl list -digest-algorithms} will display the available digest algorithms.
 * {@link https://nodejs.org/api/crypto.html#crypto_crypto_createhash_algorithm_options}
 */
export function translateHashAlg(namedHashAlg: SDHashAlg) {
    switch (namedHashAlg) {
        case "sha-256":
            return "SHA256" ;
        case "sha-256-128":
            return "SHA256-128";
        case "sha-256-120":
            return "SHA256-120";
        case "sha-256-96":
            return "SHA256-96";
        case "sha-256-64":
            return "SHA256-64";
        case "sha-256-32":
            return "SHA256-32";
        case "sha-384":
            return "SHA3-384";
        case "sha-512":
            return "SHA512";
        case "sha3-224":
            return "SHA3-224";
        case "sha3-256":
            return "SHA3-256";
        case "sha3-384":
            return "SHA384";
        case "sha3-512":
            return "SHA3-512";
        case "blake2s-256":
            return "BLAKE2s256";
        case "blake2b-256":
            return "BLAKE2b256";
        case "blake2b-512":
            return "BLAKE2b512";
        case "k12-256":
            throw new Error("Unsupported hash algorithm: k12-256.");
        case "k12-512":
            throw new Error("Unsupported hash algorithm: k12-512.");
   }
}
