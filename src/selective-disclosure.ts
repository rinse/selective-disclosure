import { SDProps } from "./SDObject";
import { SDDefaultHashAlg, SDHashAlg } from "./hash";
import { defaultCreateSalt } from "./salt";

/**
 * Options for {@link SDObject#property}.
 */
export type DisclosureOpions = {
   /**
    * Default value: {@link SDDefaultHashAlg}.
    */ 
    hashAlg?: SDHashAlg,

    /**
     * Default value: {@link createSalt}.
     */
    createSalt?: SDCreateSalt,

    /**
     * Default value: {@link JSON.stringify}
     */
    stringify?: SDStringify,
}

/**
 * Create salt.
 */
export type SDCreateSalt = () => Buffer;

/**
 * Stringify any objects.
 */
export type SDStringify = (value: unknown) => string;

// Fills options with the given payload, options, or default values and verifies consistency.
export function fillSDOptions(
    sdProps: SDProps,
    options: DisclosureOpions,
): Required<DisclosureOpions> {
    const payloadHashAlg = sdProps._sd_alg;
    const optionHashAlg = options.hashAlg;
    const hashAlg: SDHashAlg = payloadHashAlg ?? optionHashAlg ?? SDDefaultHashAlg;
    if (payloadHashAlg !== undefined && optionHashAlg !== undefined && payloadHashAlg !== optionHashAlg) {
        throw new Error(`Inconsistent hash algorithms. It is ${sdProps._sd_alg} in the given payload but ${options.hashAlg} is specified by the option.`)
    }
    return {
        hashAlg,
        createSalt: options.createSalt ?? defaultCreateSalt,
        stringify: options.stringify ?? JSON.stringify,
    };
}
