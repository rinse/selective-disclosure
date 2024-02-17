import base64url from "base64url";
import { disclosureForObjectProps, SDObject } from "./SDObject";
import { fancyStringify } from "./utils";

/**
 * > 5.2.1. Disclosures for Object Properties 
 * > The resulting Disclosure would be: WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-5.2.1}
 */
test("disclosureForObjectProps produces the matching disclosure to the example.", () => {
    const salt = "_26bc4LT-ac6q2KI6cBW5es";
    const claimName = "family_name";
    const claimValue = "Möbius";
    const actualDisclosure = disclosureForObjectProps(salt, claimName, claimValue, fancyStringify);
    expect(actualDisclosure).toBe("WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0");
});

/**
 * > 6.1. Issuance
 * > https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-6.1
 */
describe("6.1. Issuance", () => {
    const inputClaimSet = {
        "sub": "user_42",
        "given_name": "John",
        "family_name": "Doe",
        "email": "johndoe@example.com",
        "phone_number": "+1-202-555-0101",
        "phone_number_verified": true,
        "address": {
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "Anystate",
            "country": "US"
        },
        "birthdate": "1940-01-01",
        "updated_at": 1570000000,
        "nationalities": [
            "US",
            "DE"
        ]
    };
    const sdObject = SDObject.pure(inputClaimSet)
        // The nationalities array is always visible, but its contents are selectively disclosable.
        .array("nationalities", [0], { createSalt: mockCreateSalt("lklxF5jMYlGTPUovMNIvCA"), stringify: fancyStringify })
        .array("nationalities", [1], { createSalt: mockCreateSalt("nPuoQnkRFq3BIeAm7AnXFA"), stringify: fancyStringify })
        // The sub element and essential verification data (iss, iat, cnf, etc.) are always visible.
        // All other End-User claims are selectively disclosable.
        .prop(["given_name"], { createSalt: mockCreateSalt("2GLC42sKQveCfGfryNRN9w"), stringify: fancyStringify })
        .prop(["family_name"], { createSalt: mockCreateSalt("eluV5Og3gSNII8EYnsxA_A"), stringify: fancyStringify })
        .prop(["email"], { createSalt: mockCreateSalt("6Ij7tM-a5iVPGboS5tmvVA"), stringify: fancyStringify })
        .prop(["phone_number"], { createSalt: mockCreateSalt("eI8ZWm9QnKPpNPeNenHdhQ"), stringify: fancyStringify })
        .prop(["phone_number_verified"], { createSalt: mockCreateSalt("Qg_O64zqAxe412a108iroA"), stringify: fancyStringify })
        .prop(["birthdate"], { createSalt: mockCreateSalt("Pc33JM2LchcU_lHggv_ufQ"), stringify: fancyStringify })
        .prop(["updated_at"], { createSalt: mockCreateSalt("G02NSrQfjFXQ7Io09syajA"), stringify: fancyStringify })
        // For address, the Issuer is using a flat structure, i.e., all of the claims in the address claim can
        // only be disclosed in full. Other options are discussed in Section 7.
        .prop(["address"], { createSalt: mockCreateSalt("AJx-095VPrpTtN4QMOqROA"), stringify: fancyStringify })
        ;
    test("Produced disclosures match to the example", () => {
        const expectedDisclosures = [
            // US
            "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0",
            // DE
            "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0",
            // given_name
            "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
            // family_name
            "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
            // email
            "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
            // phone_number
            "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ",
            // phone_number_verified
            "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd",
            // birthdate
            "WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0",
            // updated_at
            "WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ",
            // address
            "WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
        ];
        expect(sdObject.disclosures).toEqual(expectedDisclosures);
    });
    test("Produced digests match to the example", () => {
        // The following payload is used for the SD-JWT:
        const expectedPayload = {
            "_sd": [
                "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI",
                "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
                "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI",
                "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
                "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM",
                "XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE",
                "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM",
                "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
            ],
            "iss": "https://issuer.example.com",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "user_42",
            "nationalities": [
                {
                    "...": "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"
                },
                {
                    "...": "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"
                }
            ],
            "_sd_alg": "sha-256",
            "cnf": {
                "jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                    "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
                }
            }
        }
        const actualSD = sorted(sdObject.sdObject?._sd ?? []);
        const expectedSD = sorted(expectedPayload._sd);
        expect(actualSD).toEqual(expectedSD);
        expect(sdObject.sdObject.nationalities).toEqual(expectedPayload.nationalities);
    });
});


/**
 * > 7. Considerations on Nested Data in SD-JWTs
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-7}
 */
describe("Considerations on Nested Data in SD-JWTs", () => {
    const inputClaimSet = {
        "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
        "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
            "region": "Sachsen-Anhalt",
            "country": "DE"
        }
    };

    /**
     * > 7.1. Example: Flat SD-JWT 
     * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-7.1}
     */
    describe("Flat SD-JWT", () => {
        const sdObject = SDObject.pure(inputClaimSet)
            .prop(["address"], { createSalt: mockCreateSalt("2GLC42sKQveCfGfryNRN9w"), stringify: fancyStringify });
        test("Produced disclosure matches to the example", () => {
            expect(sdObject.disclosures[0]).toBe("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIlNjaHVsc3RyLiAxMiIsICJsb2NhbGl0eSI6ICJTY2h1bHBmb3J0YSIsICJyZWdpb24iOiAiU2FjaHNlbi1BbmhhbHQiLCAiY291bnRyeSI6ICJERSJ9XQ");
        });
        test("Produced digest matches to the example", () => {
            expect(sdObject.sdObject?._sd?.at(0)).toBe("fOBUSQvo46yQO-wRwXBcGqvnbKIueISEL961_Sjd4do");
        });
    });

    /**
     * > 7.2. Example: Structured SD-JWT
     * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#section-7.2}
     */
    describe("Structured SD-JWT", () => {
        const sdObject = SDObject.pure(inputClaimSet)
            .nested("address", address =>
                SDObject.pure(address)
                    .prop(["street_address"], { createSalt: mockCreateSalt("2GLC42sKQveCfGfryNRN9w"), stringify: fancyStringify })
                    .prop(["locality"], { createSalt: mockCreateSalt("eluV5Og3gSNII8EYnsxA_A"), stringify: fancyStringify })
                    .prop(["region"], { createSalt: mockCreateSalt("6Ij7tM-a5iVPGboS5tmvVA"), stringify: fancyStringify })
                    .prop(["country"], { createSalt: mockCreateSalt("eI8ZWm9QnKPpNPeNenHdhQ"), stringify: fancyStringify })
            )
            ;
        test("Produced disclosures match to the example", () => {
            expect(sorted(sdObject.disclosures)).toEqual(sorted([
                // street_address
                "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
                // locality
                "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
                // region
                "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
                // country
                "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
            ]));
        });
        test("Produced digests matches to the example", () => {
            expect(sorted(sdObject.sdObject.address._sd ?? [])).toEqual(sorted([
                "6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0",
                "9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM",
                "KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88",
                "WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM"
            ]));
        });
    });

    /**
     * > 7.3. Example: SD-JWT with Recursive Disclosures 
     */
    describe("SD-JWT with Recursive Disclosures", () => {
        const sdObject = SDObject.pure(inputClaimSet)
            .nested("address", address =>
                SDObject.pure(address)
                    .prop(["street_address"], { createSalt: mockCreateSalt("2GLC42sKQveCfGfryNRN9w"), stringify: fancyStringify })
                    .prop(["locality"], { createSalt: mockCreateSalt("eluV5Og3gSNII8EYnsxA_A"), stringify: fancyStringify })
                    .prop(["region"], { createSalt: mockCreateSalt("6Ij7tM-a5iVPGboS5tmvVA"), stringify: fancyStringify })
                    .prop(["country"], { createSalt: mockCreateSalt("eI8ZWm9QnKPpNPeNenHdhQ"), stringify: fancyStringify })
            )
            .prop(["address"], {
                createSalt: mockCreateSalt("Qg_O64zqAxe412a108iroA"),
                stringify: value => {
                    return JSON.stringify(value, (key, value) => {
                        switch (key) {
                            case "_sd_alg": return undefined;
                            case "_sd": return sorted(value);
                            default: return value;
                        }
                    }).replaceAll(",", ", ").replaceAll(":", ": ");
                },
            })
            ;
        test("Produced disclosure match to the example", () => {
            expect(sorted(sdObject.disclosures)).toEqual(sorted([
                // street_address
                "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd",
                // locality
                "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0",
                // region
                "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd",
                // country
                "WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ",
                // address
                "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiNnZoOWJxLXpTNEdLTV83R3BnZ1ZiWXp6dTZvT0dYcm1OVkdQSFA3NVVkMCIsICI5Z2pWdVh0ZEZST0NnUnJ0TmNHVVhtRjY1cmRlemlfNkVyX2o3NmttWXlNIiwgIktVUkRQaDRaQzE5LTN0aXotRGYzOVY4ZWlkeTFvVjNhM0gxRGEyTjBnODgiLCAiV045cjlkQ0JKOEhUQ3NTMmpLQVN4VGpFeVc1bTV4NjVfWl8ycm8yamZYTSJdfV0",
            ]));
        });
    });
})

function mockCreateSalt(salt: string): () => Buffer {
    return () => base64url.toBuffer(salt);
}

function sorted<T>(array: T[]): T[] {
    return [...array].sort();
}
