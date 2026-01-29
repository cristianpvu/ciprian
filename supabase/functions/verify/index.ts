// Supabase Edge Function for NFC tag verification
// Deploy: supabase functions deploy verify

import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

// AES-CMAC implementation for NTAG 424 DNA verification
class Ntag424Crypto {
  private static hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  private static bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  private static xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(Math.min(a.length, b.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  }

  private static async aesEncrypt(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key, { name: 'AES-CBC' }, false, ['encrypt']
    );
    const iv = new Uint8Array(16);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv }, cryptoKey, data
    );
    return new Uint8Array(encrypted).slice(0, 16);
  }

  private static async aesDecrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
      'raw', key, { name: 'AES-CBC' }, false, ['decrypt']
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv }, cryptoKey, data
    );
    return new Uint8Array(decrypted);
  }

  private static generateSubkey(input: Uint8Array): Uint8Array {
    const result = new Uint8Array(16);
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

  static async calculateCmac(keyHex: string, message: Uint8Array): Promise<Uint8Array> {
    const key = this.hexToBytes(keyHex);

    // Generate subkeys
    const L = await this.aesEncrypt(key, new Uint8Array(16));
    const k1 = this.generateSubkey(L);
    const k2 = this.generateSubkey(k1);

    // Calculate CMAC
    const blockCount = Math.ceil(message.length / 16) || 1;
    const completeLastBlock = message.length > 0 && message.length % 16 === 0;

    let lastBlock = new Uint8Array(16);
    if (completeLastBlock) {
      lastBlock.set(message.slice((blockCount - 1) * 16, blockCount * 16));
      lastBlock = this.xor(lastBlock, k1);
    } else {
      const remaining = message.length % 16;
      if (message.length > 0) {
        lastBlock.set(message.slice((blockCount - 1) * 16));
      }
      lastBlock[remaining] = 0x80;
      lastBlock = this.xor(lastBlock, k2);
    }

    let x = new Uint8Array(16);
    for (let i = 0; i < blockCount - 1; i++) {
      const block = message.slice(i * 16, (i + 1) * 16);
      x = await this.aesEncrypt(key, this.xor(x, block));
    }
    x = await this.aesEncrypt(key, this.xor(x, lastBlock));

    return x;
  }

  static async decryptPiccData(metaReadKeyHex: string, encHex: string): Promise<{ uid: string; counter: number }> {
    const key = this.hexToBytes(metaReadKeyHex);
    const enc = this.hexToBytes(encHex);
    const iv = new Uint8Array(16);

    const decrypted = await this.aesDecrypt(key, iv, enc);

    const uid = this.bytesToHex(decrypted.slice(0, 7));
    const counter = decrypted[7] | (decrypted[8] << 8) | (decrypted[9] << 16);

    return { uid, counter };
  }

  static async verifySdmMac(
    fileReadKeyHex: string,
    uid: string,
    counter: number,
    cmacHex: string
  ): Promise<boolean> {
    // Build session vector
    const sv = new Uint8Array(16);
    sv[0] = 0x3C;
    sv[1] = 0xC3;
    sv[2] = 0x00;
    sv[3] = 0x01;
    sv[4] = 0x00;
    sv[5] = 0x80;

    const uidBytes = this.hexToBytes(uid);
    sv.set(uidBytes.slice(0, 7), 6);

    sv[13] = counter & 0xFF;
    sv[14] = (counter >> 8) & 0xFF;
    sv[15] = (counter >> 16) & 0xFF;

    // Derive session key
    const sessionKey = await this.calculateCmac(fileReadKeyHex, sv);
    const sessionKeyHex = this.bytesToHex(sessionKey);

    // Calculate CMAC over empty data
    const calculatedMac = await this.calculateCmac(sessionKeyHex, new Uint8Array(0));

    // Truncate (take odd bytes)
    const truncated = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      truncated[i] = calculatedMac[i * 2 + 1];
    }

    const providedMac = this.hexToBytes(cmacHex);

    // Compare
    if (truncated.length !== providedMac.length) return false;
    for (let i = 0; i < truncated.length; i++) {
      if (truncated[i] !== providedMac[i]) return false;
    }
    return true;
  }
}

serve(async (req) => {
  // Handle CORS
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const url = new URL(req.url)
    const enc = url.searchParams.get('enc')
    const cmac = url.searchParams.get('cmac')

    // If no params, show info
    if (!enc && !cmac) {
      return new Response(
        JSON.stringify({ message: 'Ciprian NFC Verification Service', status: 'ready' }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    if (!enc || !cmac) {
      return new Response(
        JSON.stringify({ valid: false, message: 'Missing verification parameters' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Create Supabase client
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const supabase = createClient(supabaseUrl, supabaseKey)

    // Get all tags to try decryption
    const { data: tags, error } = await supabase
      .from('tags')
      .select('id, uid, name, organization_id, sdm_meta_read_key, sdm_file_read_key, last_counter')

    if (error) throw error

    let verifiedTag = null
    let piccData = null

    // Try each tag
    for (const tag of tags || []) {
      try {
        const decrypted = await Ntag424Crypto.decryptPiccData(tag.sdm_meta_read_key, enc)

        if (decrypted.uid.toUpperCase() === tag.uid.toUpperCase()) {
          // Verify CMAC
          const isValid = await Ntag424Crypto.verifySdmMac(
            tag.sdm_file_read_key,
            decrypted.uid,
            decrypted.counter,
            cmac
          )

          if (isValid) {
            verifiedTag = tag
            piccData = decrypted
            break
          }
        }
      } catch {
        continue
      }
    }

    const clientIp = req.headers.get('x-forwarded-for') || 'unknown'
    const userAgent = req.headers.get('user-agent') || 'unknown'

    if (!verifiedTag || !piccData) {
      // Log failed attempt
      await supabase.rpc('log_scan', {
        p_tag_id: null,
        p_org_id: null,
        p_counter: 0,
        p_ip: clientIp,
        p_user_agent: userAgent,
        p_valid: false,
        p_failure_reason: 'Unknown tag or invalid signature'
      })

      return new Response(
        JSON.stringify({ valid: false, message: 'Invalid or unknown tag' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Check counter (anti-replay)
    if (piccData.counter <= verifiedTag.last_counter) {
      await supabase.rpc('log_scan', {
        p_tag_id: verifiedTag.id,
        p_org_id: verifiedTag.organization_id,
        p_counter: piccData.counter,
        p_ip: clientIp,
        p_user_agent: userAgent,
        p_valid: false,
        p_failure_reason: 'Replay detected'
      })

      return new Response(
        JSON.stringify({ valid: false, message: 'Replay attack detected' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      )
    }

    // Update tag counter
    await supabase.rpc('update_tag_scan', {
      p_tag_id: verifiedTag.id,
      p_counter: piccData.counter
    })

    // Log success
    await supabase.rpc('log_scan', {
      p_tag_id: verifiedTag.id,
      p_org_id: verifiedTag.organization_id,
      p_counter: piccData.counter,
      p_ip: clientIp,
      p_user_agent: userAgent,
      p_valid: true,
      p_failure_reason: null
    })

    return new Response(
      JSON.stringify({
        valid: true,
        uid: verifiedTag.uid,
        counter: piccData.counter,
        tagName: verifiedTag.name,
        message: 'Tag verified successfully',
        timestamp: new Date().toISOString()
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )

  } catch (error) {
    console.error('Verification error:', error)
    return new Response(
      JSON.stringify({ valid: false, message: 'Verification service error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    )
  }
})
