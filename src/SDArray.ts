import base64url from "base64url";
import { hash } from "./hash";
import { DisclosureOpions, SDStringify } from "./selective-disclosure";

/**
 * Translate an array to SDArray.
 */
export type SDArrayOf<A> = A extends Array<infer E>
    ? (E | SDArrayElemDigest)[]
    : never;

/**
 * The type of selectively disclosable array.
 */
export type SDArray<T> = (T | SDArrayElemDigest)[]

/**
 * 5.2.4.2. Array Elements
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.2.4.2}
 */
export type SDArrayElemDigest = { "...": string };

/**
 * 5.2.4.2. Array Elements
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.2.4.2}
 */
function arrayElementDigest(digest: string): SDArrayElemDigest {
    return { "...": digest };
}

/**
 * 5.2.2. Disclosures for Array Elements
 */ 
export function disclosureForArrayElement(salt: string, element: unknown, stringify: SDStringify): string {
    const array = [salt, element];
    const jsonEncodedArray = stringify(array);
    return base64url.encode(jsonEncodedArray);
}

export type SDArrayResult<T> = {
    sdArray: SDArray<T>,
    disclosures: string[],
}

export function sdArray<T>(array: T[], indices: number[], disclosureOptions: Required<DisclosureOpions>): SDArrayResult<T> {
    const { hashAlg, createSalt } = disclosureOptions;
    return array.reduce((acc: SDArrayResult<T>, e: T, index) => {
        if (indices.includes(index)) {
            const salt = base64url(createSalt());
            const disclosure = disclosureForArrayElement(salt, e, disclosureOptions.stringify);
            const disclosureDigest = base64url(hash(disclosure, hashAlg));
            return {
                sdArray: [...acc.sdArray, arrayElementDigest(disclosureDigest)],
                disclosures: [...acc.disclosures, disclosure],
             };
        }
        return {
            sdArray: [...acc.sdArray, e],
            disclosures: acc.disclosures,
        };
    }, { sdArray: [], disclosures: [] });
}
