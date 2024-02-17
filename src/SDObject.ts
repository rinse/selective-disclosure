import base64url from "base64url";
import { SDDefaultHashAlg, SDHashAlg, hash } from "./hash";
import { SDArrayOf, sdArray } from "./SDArray";
import { DisclosureOpions, SDStringify, fillSDOptions } from "./selective-disclosure";
import { IsUnion } from "./utils";

/**
 * Specific roperties for SD-JWT.
 *
 * > The payload MAY contain the _sd_alg key described in Section 5.1.1. 
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.1}
 * 
 * > 5.2.4.1. Object Properties
 * > Digests of Disclosures for object properties are added
 * > to an array under the new key _sd in the object.
 * > The _sd key MUST refer to an array of strings,
 * > each string being a digest of a Disclosure or a decoy
 * > digest as described in Section 5.2.5.
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-object-properties}
 */
export type SDProps = {
    _sd_alg?: SDHashAlg,
    _sd?: string[],
};

/**
 * An json object with disclosable properties.
 */
export class SDObject<T> {
    private readonly _sdObject: SDProps & T;
    private readonly _disclosures: string[];

    constructor(payload: SDProps & T, disclosures: string[]) {
        this._sdObject = payload;
        this._disclosures = disclosures;
    }

    get sdObject(): SDProps & T {
        return this._sdObject;
    }

    get disclosures(): string[] {
        return this._disclosures;
    }

    /**
     * Lift an arbitrary object to an {@link SDObject}.
     */
    static pure<T>(object: T): SDObject<T> {
        return new SDObject<T>({ ...object, _sd: [] }, []);
    }

    /**
     * Apply a function to a selectively disclosable object.
     * The {@link U} MUST NOT an {@link SDObject} or disclosures are disposed.
     * Use {@link flatMap} instead for such purpose.
     * 
     * @param f A function to transform a selectively disclosable object.
     * @returns Transformed object with disclosures kept as it is.
     */
    map<U>(f: (t: T & SDProps) => U): SDObject<U> {
        const { _sd_alg, _sd } = this._sdObject;
        return new SDObject<U>({ ...f(this._sdObject), _sd_alg, _sd }, this._disclosures);
    }

    /**
     * Apply a function to a selectively disclosable object.
     * The {@link SDObject} returned by {@link f} MUST have the consistent hashing algorithm.
     *
     * @param f A function to transform a selectively disclosable object.
     * @returns Transformed object with disclosures kept as it is.
     */
    flatMap<U>(f: (t: T & SDProps) => SDObject<U>): SDObject<U> {
        const { _sd_alg: pSdAlg, _sd: pSd } = this._sdObject;
        const newSdObj = f(this._sdObject);
        const { _sd_alg: nSdAlg, _sd: nSd } = newSdObj._sdObject;
        if ((pSdAlg ?? SDDefaultHashAlg) !== (nSdAlg ?? SDDefaultHashAlg)) {
            throw new Error("Inconsistent hashing algorithms.");
        }
        return new SDObject(
            { ...newSdObj._sdObject, _sd: [...pSd ?? [], ...nSd ?? []] },
            [...this._disclosures, ...newSdObj._disclosures]
        );
    }

    /**
     * Make specific claims selectively disclosable.
     * 
     * > 5.2.1. Disclosures for Object Properties 
     * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.2.1}
     *
     * @param claimNames Names of the claims to make selectively disclosable.
     * @param options Opional parameters to make disclosures and digests.
     * @returns {@link SDObject} with selectively disclosable claims.
     */
    prop<K extends keyof T & string>(claimNames: K[], options: DisclosureOpions = {}): SDObject<Omit<T, K>> {
        const { sdObject: payload, disclosures } = this;
        const { hashAlg, createSalt, stringify } = fillSDOptions(this.sdObject, options);
        const sdClaims = claimNames.map(claimName => {
            const salt = base64url(createSalt());
            const claimValue: T[K] = payload[claimName];
            return disclosureForObjectProps(salt, claimName, claimValue, stringify);
        }).map(disclosure => {
            const disclosureDigest = base64url(hash(disclosure, hashAlg));
            return [disclosureDigest, disclosure] as const;
        });
        const disclosureDigests = sdClaims.map(a => a[0]);
        const newPayload = { ...payload, _sd: [...(payload._sd ?? []), ...disclosureDigests], _sd_alg: hashAlg };
        for (const disclosureClaim of claimNames) {
            delete newPayload[disclosureClaim];
        }
        const newDisclosures = [...disclosures, ...sdClaims.map(a => a[1])];
        return new SDObject<Omit<T, K>>(newPayload, newDisclosures);
    }

    /**
     * Make a specific element selectively disclosable.
     * TODO: Remove @ts-ignore's
     * 
     * > 5.2.2. Disclosures for Array Elements 
     * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.2.2}
     * 
     * @param claimNames Name of a claim to make selectively disclosable, which has an array value
     * @param indices Indices of elements to make selectively disclosable.
     * @param options Opional parameters to make disclosures and digests.
     * @returns {@link SDObject} with selectively disclosable claims.
     */
    array<K extends keyof ArrayProps<T>>(
        claimName: K,
        indices: number[] = [],
        options: DisclosureOpions = {},
    ): SDObject<Omit<T, K> & SDArrayProps<T, K>> {
        const { disclosures, sdObject: payload } = this;
        const filledSDOptions = fillSDOptions(payload, options);
        const claimValueArray: (SDProps & T)[K] = payload[claimName];
        // @ts-expect-error Argument of type '(SDProps & T)[K]' is not assignable to parameter of type 'unknown[]'.
        const { disclosures: newDisclosures, sdArray: newArray } = sdArray(claimValueArray, indices, filledSDOptions);
        const b = { [claimName]: newArray } as const;
        const newPayload = { ...payload, ...b, _sd_alg: options.hashAlg } as const;
        // @ts-expect-error Argument of type 'SDProps & T & { readonly _sd_alg: SDHashAlg | undefined; }' is not assignable to parameter of type 'SDProps & Omit<T, K> & SDArrayProps<T, K>'.
        return new SDObject<Omit<T, K> & SDArrayProps<T, K>>(newPayload, [...disclosures, ...newDisclosures]);
    }

    /**
     * Make claim contents selectively disclosable individually.
     * 
     * 7.2. Example: Structured SD-JWT 
     * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-7.2}
     * 
     * TODO: Remove @ts-ignore's.
     */
    nested<K extends keyof T, U>(
        claimName: K,
        f: (claimValue: T[K]) => SDObject<U>,
    ): SDObject<Omit<T, K> & StructuredSD<T, K, SDProps & U>> {
        const { disclosures, sdObject: payload } = this;
        const claimValue = payload[claimName];
        const { disclosures: newDisclosures, sdObject: newClaimValue } = f(claimValue);
        const newPayload = {
            ...payload,
            [claimName]: newClaimValue,
        };
        // @ts-expect-error Type 'SDObject<T>' is not assignable to type 'SDObject<Omit<T, K> & StructuredSD<T, K, SDProps & U>>'.
        return new SDObject(newPayload, [...disclosures, ...newDisclosures]);
    }
}

// 5.2.1. Disclosures for Object Properties 
export function disclosureForObjectProps(salt: string, claimName: string, claimValue: unknown, stringify: SDStringify): string {
    const array = [salt, claimName, claimValue];
    const jsonEncodedArray = stringify(array);
    return base64url.encode(jsonEncodedArray);
}

// Make property types specified by K selectively disclosable array.
type SDArrayProps<T, K extends keyof ArrayProps<T>> = {
  [k in K]: SDArrayOf<T[k]>;
}

// Extract properties whose type is an array.
type ArrayProps<T> = {
    [
        P in {  // filter keyof T; (keyof T).filter(k => T[k] extends Array<infer _>)
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            [k in keyof T]: T[k] extends Array<infer _>
                ? k
                : never
        }[keyof T]
    ]: T[P]
}

// Replaces T[K] with U if K is NOT a union type.
// Replaces T[K] with T[K] | U if K is a union type.
type StructuredSD<T, K extends keyof T, U> = IsUnion<K> extends true ? { [k in K]: T[K] | U } : { [k in K]: U };
