#!/usr/bin/env python3
"""
公開預覽安全掃描 —— 發布前必跑，任一真實敏感資訊命中即禁止發布。

用法：
    python3 scan-public-safety.py .

⛔ 這支只讀檔案、只印分類統計與命中的「樣式名稱」，
   ⛔ 不把命中的原文完整印出來（避免掃描報告本身變成外洩管道），
   只印遮蔽後的片段供人工判讀。
"""
import sys, os, re

# ── ① credential scan ──────────────────────────────────────────
CREDENTIAL = {
    'GITHUB_PAT':      re.compile(r'gh[pousr]_[A-Za-z0-9]{20,}'),
    'GOOGLE_API_KEY':  re.compile(r'AIza[0-9A-Za-z_\-]{30,}'),
    'OAUTH_TOKEN':     re.compile(r'ya29\.[0-9A-Za-z_\-]{20,}'),
    'PRIVATE_KEY':     re.compile(r'BEGIN [A-Z ]*PRIVATE KEY'),
    'AWS_KEY':         re.compile(r'AKIA[0-9A-Z]{16}'),
    'BEARER':          re.compile(r'(?i)\b(bearer|authorization)\s*[:=]\s*["\']?[A-Za-z0-9._\-]{20,}'),
    'COOKIE_ASSIGN':   re.compile(r'(?i)\b(set-)?cookie\s*[:=]\s*["\'][^"\']{10,}'),
    'PASSWORD_ASSIGN': re.compile(r'(?i)\b(password|passwd|secret|api[_-]?key)\s*[:=]\s*["\'][^"\']{6,}'),
}

# ── ② identifier scan（Google 資源識別碼）────────────────────────
IDENTIFIER = {
    # Apps Script scriptId / Drive fileId / Spreadsheet ID：一長串 base64ish
    'GOOGLE_LONG_ID':  re.compile(r'\b[A-Za-z0-9_\-]{25,}\b'),
    'DEPLOYMENT_ID':   re.compile(r'AKfycb[A-Za-z0-9_\-]{10,}'),
    'FINGERPRINT_HEX': re.compile(r'\b[0-9a-f]{32,}\b'),
}

# ── ③ Email scan ────────────────────────────────────────────────
EMAIL = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
ALLOWED_EMAIL_DOMAIN = 'example.invalid'          # ⭐ 唯一合法網域

# ── ④ URL scan ──────────────────────────────────────────────────
URL = re.compile(r'https?://[^\s"\'<>)\]]+')
# ⭐ 只放行兩個：假資料網域，以及**這份預覽自己的公開網址**（它本來就是要給人點的）。
#    ⛔ 任何其他主機都算命中——deployment URL、Drive、試算表、追蹤碼全部擋在這裡。
ALLOWED_URL_HOSTS = {'example.invalid', 'ws19135.github.io'}

# ── ⑤ absolute-path scan ────────────────────────────────────────
ABS_PATH = {
    'MAC_HOME':   re.compile(r'/Users/[A-Za-z0-9._\-]+'),
    'TMP_PATH':   re.compile(r'/private/tmp/[A-Za-z0-9._\-/]+'),
    'WIN_PATH':   re.compile(r'[A-Z]:\\\\?[A-Za-z0-9._\-\\]+'),
}

# ── ⑥ network-call scan ─────────────────────────────────────────
NETWORK = {
    'FETCH':          re.compile(r'\bfetch\s*\('),
    'XHR':            re.compile(r'XMLHttpRequest'),
    'WEBSOCKET':      re.compile(r'\bWebSocket\s*\('),
    'GOOGLE_SCRIPT':  re.compile(r'google\.script\.run'),
    'SEND_BEACON':    re.compile(r'navigator\.sendBeacon'),
    'EVENT_SOURCE':   re.compile(r'\bEventSource\s*\('),
    'IMPORT_DYNAMIC': re.compile(r'\bimport\s*\('),
    'EXTERNAL_SRC':   re.compile(r'(?:src|href)\s*=\s*["\']https?://'),
    'CSS_IMPORT':     re.compile(r'@import\b'),
    'FORM_ACTION':    re.compile(r'<form[^>]*\baction\s*='),
}

# ── ⑦ runtime source leakage scan ───────────────────────────────
# 產品後端的識別特徵。⛔ 這些一個都不該出現在公開預覽裡。
LEAKAGE = {
    'GAS_SERVICE':      re.compile(r'\b(SpreadsheetApp|PropertiesService|DriveApp|LockService|'
                                   r'HtmlService|ScriptApp|UrlFetchApp|Session\.getActiveUser)\b'),
    'BACKEND_SYMBOL':   re.compile(r'\b(SheetsStore|StorageAdapter|CommandKernel|AuditService|'
                                   r'Bootstrap\.run|guardRead|editorialPublicIntake|EditorialCore)\b'),
    'WEB_COMMAND':      re.compile(r'\bwc[A-Z][A-Za-z]+\s*\('),
    'CAPABILITY':       re.compile(r'\bCAP\.[A-Z_]+'),
    'ROLE_FINGERPRINT': re.compile(r'ROLE_DIRECTORY_CHECKSUM|role[_-]directory[_-]fingerprint'),
    'PRIVATE_REPO':     re.compile(r'sdh-book-interview-invitation-system|sdh-promotion-erp|winnie-ai-backup'),
    'BUILD_HASH':       re.compile(r'NORMALIZED_PROJECT_HASH'),
}

TEXT_EXT = {'.html', '.htm', '.css', '.js', '.md', '.json', '.txt', '.svg'}
SKIP_DIRS = {'.git', 'node_modules'}


def mask(s, keep=6):
    s = s.strip()
    return s if len(s) <= keep else s[:keep] + '…(' + str(len(s)) + ' 字)'


def files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in sorted(fns):
            if os.path.splitext(fn)[1].lower() in TEXT_EXT:
                yield os.path.join(dp, fn)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    # 自己不掃自己——這支腳本裡本來就寫滿了樣式字串
    me = os.path.abspath(__file__)
    blocking, review = [], []

    def scan(group, table, path, text, blocking_group=True):
        for name, pat in table.items():
            for m in pat.finditer(text):
                yield group, name, os.path.relpath(path, root), mask(m.group(0)), blocking_group

    hits = []
    for p in files(root):
        if os.path.abspath(p) == me:
            continue
        text = open(p, encoding='utf-8', errors='replace').read()
        rel = os.path.relpath(p, root)

        hits += list(scan('① credential', CREDENTIAL, p, text))
        hits += list(scan('⑤ absolute-path', ABS_PATH, p, text))
        hits += list(scan('⑥ network-call', NETWORK, p, text))
        hits += list(scan('⑦ runtime-leakage', LEAKAGE, p, text))

        # identifier：長 ID 誤報極多（CSS class、base64 都會中），逐一過濾
        for name, pat in IDENTIFIER.items():
            for m in pat.finditer(text):
                v = m.group(0)
                if name == 'GOOGLE_LONG_ID':
                    # 只有「同時含大小寫與數字、且不是常見英文字」才算可疑
                    if not (any(c.isupper() for c in v) and any(c.islower() for c in v)
                            and any(c.isdigit() for c in v)):
                        continue
                    if re.fullmatch(r'[A-Za-z]+', v):
                        continue
                hits.append(('② identifier', name, rel, mask(v), True))

        # Email：只允許 example.invalid
        for m in EMAIL.finditer(text):
            v = m.group(0)
            ok = v.lower().endswith('@' + ALLOWED_EMAIL_DOMAIN)
            hits.append(('③ email', 'REAL_EMAIL' if not ok else 'SYNTHETIC_OK',
                         rel, v if ok else mask(v), not ok))

        # URL：只允許 example.invalid
        for m in URL.finditer(text):
            v = m.group(0)
            host = re.sub(r'^https?://', '', v).split('/')[0].split(':')[0].lower()
            ok = host in ALLOWED_URL_HOSTS
            hits.append(('④ url', 'EXTERNAL_URL' if not ok else 'SYNTHETIC_OK',
                         rel, v, not ok))

    for h in hits:
        (blocking if h[4] else review).append(h)

    groups = ['① credential', '② identifier', '③ email', '④ url',
              '⑤ absolute-path', '⑥ network-call', '⑦ runtime-leakage']
    print('%-20s %8s %8s' % ('掃描項目', '禁止發布', '通過'))
    print('-' * 40)
    for g in groups:
        b = len([h for h in blocking if h[0] == g])
        r = len([h for h in review if h[0] == g])
        print('%-20s %8s %8s' % (g, ('⛔ %d' % b) if b else '✅ 0', r))

    if blocking:
        print('\n⛔ 命中明細（已遮蔽）：')
        for g, n, f, v, _ in blocking:
            print('  %-18s %-18s %-40s %s' % (g, n, f, v))
        print('\nPUBLIC_SAFETY_SCAN = FAIL —— ⛔ 禁止發布')
        sys.exit(1)

    print('\nPUBLIC_SAFETY_SCAN = PASS —— 七項全綠，可發布')


if __name__ == '__main__':
    main()
