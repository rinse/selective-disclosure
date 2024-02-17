import base64url from "base64url";
import { sdArray } from "./SDArray";
import { fancyStringify } from "./utils";

/**
 * > 5.2.2. Disclosures for Array Elements 
 * > The resulting Disclosure would be: WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.2.2}
 */
test("sdArray produces the matching disclosure to the example.", () => {
    const array = ["DE", "FR"];
    const base64urlEncodedSalt = "lklxF5jMYlGTPUovMNIvCA";
    const actual = sdArray(array, [1], {
        hashAlg: "sha-256",
        createSalt: () => base64url.toBuffer(base64urlEncodedSalt),
        stringify: fancyStringify,
    });
    expect(actual.disclosures[0]).toBe("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0");
});

/**
 * > 5.2.3. Hashing Disclosures 
 * > The SHA-256 digest of the Disclosure WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0 would be w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs. 
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.2.3}
 */
test("sdArray produces the matching digest to the example.", () => {
    const array = ["DE", "FR"];
    const base64urlEncodedSalt = "lklxF5jMYlGTPUovMNIvCA";
    const actual = sdArray(array, [1], {
        hashAlg: "sha-256",
        createSalt: () => base64url.toBuffer(base64urlEncodedSalt),
        stringify: fancyStringify,
    });
    expect(actual.sdArray[1]).toEqual({ "...": "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs" });
});
