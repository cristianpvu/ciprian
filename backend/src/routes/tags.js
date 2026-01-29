const express = require('express');
const supabase = require('../utils/supabase');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// Toate rutele necesită autentificare
router.use(authenticate);

/**
 * GET /api/tags
 * Listează cipurile user-ului
 */
router.get('/', async (req, res) => {
    try {
        const { data: tags, error } = await supabase
            .from('tags')
            .select('id, uid, name, description, base_url, scan_count, last_scan_at, created_at')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.json({
            tags: tags.map(tag => ({
                id: tag.id,
                uid: tag.uid,
                name: tag.name,
                description: tag.description,
                baseUrl: tag.base_url,
                scanCount: tag.scan_count,
                lastScan: tag.last_scan_at,
                createdAt: tag.created_at
            })),
            total: tags.length
        });

    } catch (error) {
        console.error('Get tags error:', error);
        res.status(500).json({ error: 'Failed to get tags' });
    }
});

/**
 * POST /api/tags
 * Înregistrează un cip nou
 */
router.post('/', async (req, res) => {
    try {
        const {
            uid,
            name,
            description,
            baseUrl,
            appMasterKey,
            sdmMetaReadKey,
            sdmFileReadKey
        } = req.body;

        if (!uid || !appMasterKey || !sdmMetaReadKey || !sdmFileReadKey) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Verifică dacă UID-ul există deja (global, nu doar pt user)
        const { data: existing } = await supabase
            .from('tags')
            .select('id')
            .eq('uid', uid.toUpperCase())
            .single();

        if (existing) {
            return res.status(409).json({ error: 'Tag with this UID already exists' });
        }

        // Inserează tag-ul
        const { data: tag, error } = await supabase
            .from('tags')
            .insert({
                user_id: req.user.id,
                uid: uid.toUpperCase(),
                name: name || 'Unnamed Tag',
                description: description || null,
                base_url: baseUrl,
                app_master_key: appMasterKey,
                sdm_meta_read_key: sdmMetaReadKey,
                sdm_file_read_key: sdmFileReadKey
            })
            .select('id')
            .single();

        if (error) throw error;

        res.status(201).json({
            success: true,
            tagId: tag.id,
            message: 'Tag registered successfully'
        });

    } catch (error) {
        console.error('Register tag error:', error);
        res.status(500).json({ error: 'Failed to register tag' });
    }
});

/**
 * GET /api/tags/:id
 * Detalii despre un cip
 */
router.get('/:id', async (req, res) => {
    try {
        const { data: tag, error } = await supabase
            .from('tags')
            .select('id, uid, name, description, base_url, scan_count, last_scan_at, created_at')
            .eq('id', req.params.id)
            .eq('user_id', req.user.id)
            .single();

        if (error || !tag) {
            return res.status(404).json({ error: 'Tag not found' });
        }

        res.json({
            id: tag.id,
            uid: tag.uid,
            name: tag.name,
            description: tag.description,
            baseUrl: tag.base_url,
            scanCount: tag.scan_count,
            lastScan: tag.last_scan_at,
            createdAt: tag.created_at
        });

    } catch (error) {
        console.error('Get tag error:', error);
        res.status(500).json({ error: 'Failed to get tag' });
    }
});

/**
 * GET /api/tags/:id/keys
 * Obține cheile unui cip (pentru factory reset)
 */
router.get('/:id/keys', async (req, res) => {
    try {
        const { data: tag, error } = await supabase
            .from('tags')
            .select('id, uid, app_master_key, sdm_meta_read_key, sdm_file_read_key')
            .eq('id', req.params.id)
            .eq('user_id', req.user.id)
            .single();

        if (error || !tag) {
            return res.status(404).json({ error: 'Tag not found' });
        }

        res.json({
            id: tag.id,
            uid: tag.uid,
            appMasterKey: tag.app_master_key,
            sdmMetaReadKey: tag.sdm_meta_read_key,
            sdmFileReadKey: tag.sdm_file_read_key
        });

    } catch (error) {
        console.error('Get tag keys error:', error);
        res.status(500).json({ error: 'Failed to get tag keys' });
    }
});

/**
 * DELETE /api/tags/:id
 * Șterge un cip
 */
router.delete('/:id', async (req, res) => {
    try {
        const { error } = await supabase
            .from('tags')
            .delete()
            .eq('id', req.params.id)
            .eq('user_id', req.user.id);

        if (error) throw error;

        res.json({ success: true, message: 'Tag deleted' });

    } catch (error) {
        console.error('Delete tag error:', error);
        res.status(500).json({ error: 'Failed to delete tag' });
    }
});

module.exports = router;
