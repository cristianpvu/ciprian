const express = require('express');
const supabase = require('../utils/supabase');
const Ntag424Crypto = require('../utils/crypto');

const router = express.Router();

/**
 * GET /verify
 * Endpoint PUBLIC pentru verificarea cipurilor scanate
 * Acesta e apelat când cineva scanează un cip NFC
 *
 * Query params (plaintext mode - sdmMetaReadPerm = ACCESS_EVERYONE):
 * - uid: UID-ul tag-ului (14 caractere hex)
 * - ctr: Counter-ul (6 caractere hex)
 * - cmac: CMAC pentru verificare (16 caractere hex)
 *
 * Query params (encrypted mode - pentru viitor):
 * - enc: Date criptate (conține UID + counter)
 * - cmac: CMAC pentru verificare
 */
router.get('/', async (req, res) => {
    const { uid, ctr, cmac, enc } = req.query;

    // Fără parametri - returnează info
    if (!uid && !ctr && !cmac && !enc) {
        return res.json({
            service: 'Ciprian NFC Verification',
            status: 'ready',
            version: '1.0.0'
        });
    }

    // Plaintext mode: uid + ctr + cmac
    if (uid && ctr && cmac) {
        return handlePlaintextVerification(req, res, uid, ctr, cmac);
    }

    // Encrypted mode: enc + cmac (pentru viitor)
    if (enc && cmac) {
        return handleEncryptedVerification(req, res, enc, cmac);
    }

    // Parametri lipsă
    return res.status(400).json({
        valid: false,
        message: 'Missing verification parameters. Required: uid, ctr, cmac'
    });
});

/**
 * Verificare în modul plaintext (sdmMetaReadPerm = ACCESS_EVERYONE)
 * UID și Counter sunt în clar, doar CMAC e pentru verificare
 */
async function handlePlaintextVerification(req, res, uid, ctr, cmac) {
    try {
        const uidUpper = uid.toUpperCase();
        const counter = parseInt(ctr, 16);

        console.log(`Verifying tag: UID=${uidUpper}, Counter=${counter}, CMAC=${cmac}`);

        // Caută tag-ul după UID
        const { data: tag, error } = await supabase
            .from('tags')
            .select('id, uid, name, user_id, sdm_file_read_key, last_counter, scan_count')
            .eq('uid', uidUpper)
            .single();

        const clientIp = req.headers['x-forwarded-for'] || req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        if (error || !tag) {
            console.log('Tag not found in database:', uidUpper);
            await logScan(null, null, counter, clientIp, userAgent, false, 'Unknown tag');
            return res.status(401).json({
                valid: false,
                message: 'Unknown tag'
            });
        }

        // Verifică CMAC folosind sdm_file_read_key (Key3 în exemplul nostru)
        // Pentru SDM plaintext, MAC-ul se calculează pe: UID || Counter
        const macKey = tag.sdm_file_read_key || '00000000000000000000000000000000';
        const isValidMac = Ntag424Crypto.verifySdmMac(macKey, uid, ctr, cmac);

        if (!isValidMac) {
            console.log('Invalid CMAC for tag:', uidUpper);
            await logScan(tag.id, tag.user_id, counter, clientIp, userAgent, false, 'Invalid CMAC');
            return res.status(401).json({
                valid: false,
                message: 'Invalid signature'
            });
        }

        // Verificare anti-replay (counter)
        if (counter <= (tag.last_counter || 0)) {
            console.log('Replay detected:', counter, '<=', tag.last_counter);
            await logScan(tag.id, tag.user_id, counter, clientIp, userAgent, false, 'Replay detected');
            return res.status(401).json({
                valid: false,
                message: 'Replay attack detected'
            });
        }

        // Actualizează counter-ul
        await supabase
            .from('tags')
            .update({
                last_counter: counter,
                scan_count: (tag.scan_count || 0) + 1,
                last_scan_at: new Date().toISOString()
            })
            .eq('id', tag.id);

        // Loghează scanarea reușită
        await logScan(tag.id, tag.user_id, counter, clientIp, userAgent, true, null);

        // Succes!
        console.log('Tag verified successfully:', uidUpper);
        res.json({
            valid: true,
            uid: tag.uid,
            counter: counter,
            tagName: tag.name,
            message: 'Tag verified successfully',
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Plaintext verification error:', error);
        res.status(500).json({
            valid: false,
            message: 'Verification service error'
        });
    }
}

/**
 * Verificare în modul criptat (sdmMetaReadPerm = ACCESS_KEYx)
 * UID și Counter sunt criptate în 'enc'
 */
async function handleEncryptedVerification(req, res, enc, cmac) {
    try {
        // Obține toate cipurile pentru a încerca verificarea
        const { data: tags, error } = await supabase
            .from('tags')
            .select('id, uid, name, user_id, sdm_meta_read_key, sdm_file_read_key, last_counter, scan_count');

        if (error) throw error;

        let verifiedTag = null;
        let piccData = null;

        // Încearcă fiecare cip
        for (const tag of tags || []) {
            try {
                const result = Ntag424Crypto.verifySdm(
                    tag.sdm_meta_read_key,
                    tag.sdm_file_read_key,
                    enc,
                    cmac
                );

                if (result.valid && result.uid.toUpperCase() === tag.uid.toUpperCase()) {
                    verifiedTag = tag;
                    piccData = result;
                    break;
                }
            } catch (e) {
                continue;
            }
        }

        const clientIp = req.headers['x-forwarded-for'] || req.ip || 'unknown';
        const userAgent = req.headers['user-agent'] || 'unknown';

        // Cip necunoscut sau semnătură invalidă
        if (!verifiedTag || !piccData) {
            await logScan(null, null, 0, clientIp, userAgent, false, 'Unknown tag or invalid signature');
            return res.status(401).json({
                valid: false,
                message: 'Invalid or unknown tag'
            });
        }

        // Verificare anti-replay (counter)
        if (piccData.counter <= (verifiedTag.last_counter || 0)) {
            await logScan(verifiedTag.id, verifiedTag.user_id, piccData.counter, clientIp, userAgent, false, 'Replay detected');
            return res.status(401).json({
                valid: false,
                message: 'Replay attack detected'
            });
        }

        // Actualizează counter-ul
        await supabase
            .from('tags')
            .update({
                last_counter: piccData.counter,
                scan_count: (verifiedTag.scan_count || 0) + 1,
                last_scan_at: new Date().toISOString()
            })
            .eq('id', verifiedTag.id);

        // Loghează scanarea reușită
        await logScan(verifiedTag.id, verifiedTag.user_id, piccData.counter, clientIp, userAgent, true, null);

        // Succes!
        res.json({
            valid: true,
            uid: verifiedTag.uid,
            counter: piccData.counter,
            tagName: verifiedTag.name,
            message: 'Tag verified successfully',
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Encrypted verification error:', error);
        res.status(500).json({
            valid: false,
            message: 'Verification service error'
        });
    }
}

/**
 * Loghează o scanare
 */
async function logScan(tagId, userId, counter, ip, userAgent, valid, failureReason) {
    try {
        await supabase
            .from('scan_logs')
            .insert({
                tag_id: tagId,
                user_id: userId,
                counter: counter,
                ip_address: ip,
                user_agent: userAgent,
                valid: valid,
                failure_reason: failureReason
            });
    } catch (error) {
        console.error('Failed to log scan:', error);
    }
}

module.exports = router;
