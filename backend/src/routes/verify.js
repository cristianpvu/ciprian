const express = require('express');
const supabase = require('../utils/supabase');
const Ntag424Crypto = require('../utils/crypto');

const router = express.Router();

/**
 * GET /verify
 * Endpoint PUBLIC pentru verificarea cipurilor scanate
 * Acesta e apelat când cineva scanează un cip NFC
 *
 * Query params:
 * - enc: Date criptate (conține UID + counter)
 * - cmac: CMAC pentru verificare
 */
router.get('/', async (req, res) => {
    const { enc, cmac } = req.query;

    // Fără parametri - returnează info
    if (!enc && !cmac) {
        return res.json({
            service: 'Ciprian NFC Verification',
            status: 'ready',
            version: '1.0.0'
        });
    }

    // Parametri lipsă
    if (!enc || !cmac) {
        return res.status(400).json({
            valid: false,
            message: 'Missing verification parameters'
        });
    }

    try {
        // Obține toate cipurile pentru a încerca verificarea
        const { data: tags, error } = await supabase
            .from('tags')
            .select('id, uid, name, user_id, sdm_meta_read_key, sdm_file_read_key, last_counter');

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
        if (piccData.counter <= verifiedTag.last_counter) {
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
                scan_count: verifiedTag.scan_count + 1,
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
        console.error('Verification error:', error);
        res.status(500).json({
            valid: false,
            message: 'Verification service error'
        });
    }
});

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
