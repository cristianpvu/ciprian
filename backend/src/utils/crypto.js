/**
 * NTAG 424 DNA Cryptographic utilities
 * AES-CMAC verification for SDM
 */

const crypto = require('crypto');

class Ntag424Crypto {

    static hexToBytes(hex) {
        const bytes = Buffer.alloc(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    static bytesToHex(bytes) {
        return Buffer.from(bytes).toString('hex').toUpperCase();
    }

    static xor(a, b) {
        const result = Buffer.alloc(Math.min(a.length, b.length));
        for (let i = 0; i < result.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    static aesEncrypt(key, data) {
        const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
        cipher.setAutoPadding(false);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    }

    static aesDecryptCBC(key, iv, data) {
        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    static generateSubkey(input) {
        const result = Buffer.alloc(16);
        let carry = 0;
        for (let i = 15; i >= 0; i--) {
            const b = (input[i] & 0xFF) << 1;
            result[i] = (b | carry) & 0xFF;
            carry = (b >> 8) & 1;
        }
        if ((input[0] & 0x80) !== 0) {
            result[15] ^= 0x87;
        }
        return result;
    }

    static calculateCmac(keyHex, message) {
        const key = this.hexToBytes(keyHex);
        const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.alloc(0);

        // Generate subkeys
        const L = this.aesEncrypt(key, Buffer.alloc(16));
        const k1 = this.generateSubkey(L);
        const k2 = this.generateSubkey(k1);

        // Calculate CMAC
        const blockCount = Math.ceil(messageBuffer.length / 16) || 1;
        const completeLastBlock = messageBuffer.length > 0 && messageBuffer.length % 16 === 0;

        let lastBlock = Buffer.alloc(16);
        if (completeLastBlock) {
            messageBuffer.copy(lastBlock, 0, (blockCount - 1) * 16, blockCount * 16);
            lastBlock = this.xor(lastBlock, k1);
        } else {
            const remaining = messageBuffer.length % 16;
            if (messageBuffer.length > 0) {
                messageBuffer.copy(lastBlock, 0, (blockCount - 1) * 16);
            }
            lastBlock[remaining] = 0x80;
            lastBlock = this.xor(lastBlock, k2);
        }

        let x = Buffer.alloc(16);
        for (let i = 0; i < blockCount - 1; i++) {
            const block = messageBuffer.slice(i * 16, (i + 1) * 16);
            x = this.aesEncrypt(key, this.xor(x, block));
        }
        x = this.aesEncrypt(key, this.xor(x, lastBlock));

        return x;
    }

    static decryptPiccData(metaReadKeyHex, encHex) {
        const key = this.hexToBytes(metaReadKeyHex);
        const enc = this.hexToBytes(encHex);
        const iv = Buffer.alloc(16);

        const decrypted = this.aesDecryptCBC(key, iv, enc);

        const uid = this.bytesToHex(decrypted.slice(0, 7));
        const counter = decrypted[7] | (decrypted[8] << 8) | (decrypted[9] << 16);

        return { uid, counter };
    }

    /**
     * Verifică CMAC pentru SDM în modul plaintext
     * Când sdmMetaReadPerm = ACCESS_EVERYONE, UID și Counter sunt în clar
     * 
     * @param {string} fileReadKeyHex - Cheia pentru MAC (Key3 - factory key = 00...00)
     * @param {string} uidHex - UID în hex (14 caractere)
     * @param {string} ctrHex - Counter în hex (6 caractere)
     * @param {string} cmacHex - CMAC primit (16 caractere)
     */
    static verifySdmMac(fileReadKeyHex, uidHex, ctrHex, cmacHex) {
        try {
            // Parse UID și counter
            const uid = this.hexToBytes(uidHex);
            const counterValue = parseInt(ctrHex, 16);
            
            // Counter în format little-endian (3 bytes)
            const counter = Buffer.alloc(3);
            counter[0] = counterValue & 0xFF;
            counter[1] = (counterValue >> 8) & 0xFF;
            counter[2] = (counterValue >> 16) & 0xFF;

            // Construiește Session Vector (SV) conform NXP AN12196
            // SV = 3C || C3 || 00 || 01 || 00 || 80 || UID (7 bytes) || Counter (3 bytes)
            const sv = Buffer.alloc(16);
            sv[0] = 0x3C;
            sv[1] = 0xC3;
            sv[2] = 0x00;
            sv[3] = 0x01;
            sv[4] = 0x00;
            sv[5] = 0x80;
            uid.copy(sv, 6, 0, 7);
            counter.copy(sv, 13, 0, 3);

            // Derivă Session Key: SessionKey = CMAC(FileReadKey, SV)
            const sessionKey = this.calculateCmac(fileReadKeyHex, sv);
            const sessionKeyHex = this.bytesToHex(sessionKey);

            // Pentru SDM plaintext fără encrypted file data:
            // MAC se calculează pe datele de la SDMMACInputOffset până la SDMMACOffset
            // În cazul nostru (fără ^), MAC-ul e calculat doar pe PICC data
            // Dar în modul plaintext cu sdmMacInputOffset == sdmMacOffset, e pe nimic (empty)
            
            // Calculează CMAC pe date goale (zero-length MAC input)
            const calculatedMac = this.calculateCmac(sessionKeyHex, Buffer.alloc(0));

            // Truncate: ia bytes de pe pozițiile impare (1, 3, 5, 7, 9, 11, 13, 15)
            const truncated = Buffer.alloc(8);
            for (let i = 0; i < 8; i++) {
                truncated[i] = calculatedMac[i * 2 + 1];
            }

            const providedMac = this.hexToBytes(cmacHex);

            console.log('MAC Verification:');
            console.log('  UID:', uidHex);
            console.log('  Counter:', ctrHex, '=', counterValue);
            console.log('  Key:', fileReadKeyHex);
            console.log('  SV:', this.bytesToHex(sv));
            console.log('  SessionKey:', sessionKeyHex);
            console.log('  Calculated MAC (full):', this.bytesToHex(calculatedMac));
            console.log('  Calculated MAC (truncated):', this.bytesToHex(truncated));
            console.log('  Provided MAC:', cmacHex);
            console.log('  Match:', truncated.equals(providedMac));

            return truncated.equals(providedMac);
        } catch (error) {
            console.error('verifySdmMac error:', error);
            return false;
        }
    }

    static verifySdm(metaReadKeyHex, fileReadKeyHex, encHex, cmacHex) {
        try {
            const piccData = this.decryptPiccData(metaReadKeyHex, encHex);
            const isValid = this.verifySdmMac(fileReadKeyHex, piccData.uid, piccData.counter, cmacHex);

            return {
                valid: isValid,
                uid: piccData.uid,
                counter: piccData.counter
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }
}

module.exports = Ntag424Crypto;
