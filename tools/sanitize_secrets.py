import asyncio
import os
import sys
import re

sys.path.insert(0, '/app')
from app.database import domains_col

VALID_TYPES = {
    'Google API Key', 'AWS Access Key', 'AWS Secret Key',
    'JWT Token', 'Bearer Token', 'Stripe Key', 'Firebase Key',
    'Slack Webhook', 'GitHub Token', 'SSH Private Key'
}

def is_valid_secret(sec):
    if not isinstance(sec, dict):
        return False
    stype = sec.get("type", "")
    if stype not in VALID_TYPES:
        return False
        
    val = str(sec.get("value", "")).strip().strip('"\'`')
    if not val or len(val) < 12:
        return False

    # Reject URLs, endpoints, paths, and scripts
    if val.startswith(('http://', 'https://', '/', './', '../', '[Discovered')):
        return False
    if any(val.lower().endswith(ext) for ext in ['.js', '.css', '.html', '.png', '.jpg', '.jpeg', '.svg', '.json', '.map', '.wasm']):
        return False
        
    # Reject code fragments and variable names
    low = val.lower()
    for bad in ['recaptcha', 'challenge', 'qrcode', 'hidden', 'javascript', 'function', 'undefined', 'null', 'placeholder', 'default', 'element', 'variable', 'redirect', 'plugin']:
        if bad in low:
            return False
            
    # Reject plain alphabetic words without digits/symbols
    if re.match(r'^[a-zA-Z]+$', val):
        return False

    # Bearer token validation
    if stype == 'Bearer Token':
        token_part = val[7:].strip() if low.startswith('bearer ') else val
        if token_part.lower() in ['token', 'undefined', 'null', 'string', 'test', 'bearer', 'accesstoken', 'access_token', 'jwt']:
            return False
        if len(token_part) < 20:
            return False

    return True

async def sanitize_all():
    cursor = domains_col.find({})
    total_cleaned = 0
    total_valid_remaining = 0

    async for doc in cursor:
        doc_id = doc['_id']
        updates = {}
        web_apps = doc.get('web_applications', []) or []
        web_apps_changed = False

        for app in web_apps:
            djs = app.get('dynamic_js')
            if isinstance(djs, dict):
                raw = djs.get('extracted_secrets', []) or []
                valid = [s for s in raw if is_valid_secret(s)]
                if len(valid) != len(raw) or djs.get('extracted_secrets_count', 0) != len(valid):
                    djs['extracted_secrets'] = valid
                    djs['extracted_secrets_count'] = len(valid)
                    # Clean scripts
                    for sc in djs.get('scripts', []) or []:
                        if len(valid) == 0:
                            sc['secrets_found'] = 0
                    web_apps_changed = True
                    total_cleaned += (len(raw) - len(valid))
                    total_valid_remaining += len(valid)
                    print(f"Webapp {doc.get('domain')} / {app.get('target')}: {len(valid)} valid secrets (purged {len(raw) - len(valid)})")

        if web_apps_changed:
            updates['web_applications'] = web_apps

        infra_djs = (doc.get('infrastructure') or {}).get('dynamic_js')
        if isinstance(infra_djs, dict):
            raw = infra_djs.get('extracted_secrets', []) or []
            valid = [s for s in raw if is_valid_secret(s)]
            if len(valid) != len(raw) or infra_djs.get('extracted_secrets_count', 0) != len(valid):
                infra_djs['extracted_secrets'] = valid
                infra_djs['extracted_secrets_count'] = len(valid)
                for sc in infra_djs.get('scripts', []) or []:
                    if len(valid) == 0:
                        sc['secrets_found'] = 0
                updates['infrastructure.dynamic_js'] = infra_djs
                total_cleaned += (len(raw) - len(valid))
                total_valid_remaining += len(valid)
                print(f"Infra {doc.get('domain')}: {len(valid)} valid secrets")

        if updates:
            await domains_col.update_one({'_id': doc_id}, {'$set': updates})

    print(f"Sanitization complete! Total false positives purged: {total_cleaned}. Valid secrets remaining: {total_valid_remaining}")

if __name__ == '__main__':
    asyncio.run(sanitize_all())
