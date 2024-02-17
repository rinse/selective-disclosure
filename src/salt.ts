import { randomBytes } from "crypto";

/**
 * Create the given length of salt.
 *
 * @param bytesOfSalt The length of salt in bytes.
 * @returns Randomly generated salt with the specific size.
 */
export function createSalt(bytesOfSalt: number): Buffer {
    inspectSizeOfSalt(bytesOfSalt);
    return randomBytes(bytesOfSalt);
}

// TODO: Is this preferred ?
export function createSaltAsync(bytesOfSalt: number): Promise<Buffer> {
    inspectSizeOfSalt(bytesOfSalt);
    return new Promise<Buffer>((resolve, reject) => {
        randomBytes(bytesOfSalt, (err, buf) => {
            err !== null ? reject(err) : resolve(buf);
        });
    });
}

const SDDefaultBytesOfSalt: number = 32;

export function defaultCreateSalt(): Buffer {
    return createSalt(SDDefaultBytesOfSalt);
}

/**
 * 11.4. Minimum length of the salt
 * > The RECOMMENDED minimum length of the randomly-generated portion of the salt is 128 bits.
 * {@link https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html#name-minimum-length-of-the-salt}
 *
 * @param bytesSalt 
 * @returns 
 */
function inspectSizeOfSalt(bytesSalt: number): number {
    if (bytesSalt < 16) {
        console.warn("The RECOMMENDED minimum length of the randomly-generated portion of the salt is 128 bits.");
    }
    return bytesSalt;
}
