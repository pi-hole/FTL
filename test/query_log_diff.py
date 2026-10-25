#!/usr/bin/env python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine - auxiliary files
# Differential test of /api/queries: every request is answered from memory
# and, with disk=true, from the on-disk database. FTL imports the fixture at
# startup, so both hold the same rows and have to give the same result
#
# Usage: query_log_diff.py generate <empty database created by FTL> [--in-order]
#        query_log_diff.py compare <url> [--excludes] [--strict-names]
#        query_log_diff.py paging <url> [--strict-names]
#        query_log_diff.py time-order <url>
#        query_log_diff.py live <url> <DNS port> <file>
#        query_log_diff.py stored <url> <file>
#        query_log_diff.py upstream <port>
# test/query_log_diff.sh starts FTL on the fixtures and runs them
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

import http.client
import itertools
import json
import random
import sqlite3
import sys
import time
import urllib.parse

FILLER = 10050  # one domain and client, more rows than the 10000-row cap
RICH = 760      # every status, reply type and DNSSEC state, types and EDE codes
FILLER_DOMAIN = 'filler.example'
# >= 100: unmapped, 100 + qtype, 100 itself is qtype 0
TYPES = list(range(1, 14)) + [15, 16, 100, 113, 199, 357, 65635]
EDES = [None, -1, 0, 1, 3, 6, 9, 15, 18, 22, 29, 49152]
DOMAINS = ['example.com', 'www.example.com', 'api.example.com', 'example.org', 'mail.example.org',
           'tracker.net', 'ads.tracker.net', 'cdn.tracker.net', '_dmarc.example.com',
           '_sip._tcp.example.com', 'a_b.example.net', 'axb.example.net', 'percent%sign.example',
           'back\\slash.example', 'xn--bcher-kva.example', 'hidden', 'localhost', 'pi.hole',
           '10.1.168.192.in-addr.arpa', 'deep.sub.domain.example.com', '', 'Upper.Example.COM',
           '.'.join(['l' * 63, 'o' * 63, 'n' * 63, 'g' * 49, 'example'])]
CNAMES = ['cname-target.tracker.net', 'blocked.cname.example', 'hidden']
# 0.0.0.0 is how privacy level 2 stores a client
CLIENTS = [('192.168.1.10', 'desktop.lan'), ('192.168.1.11', ''), ('192.168.1.12', ''),
           ('10.0.0.5', 'laptop_old'), ('127.0.0.1', 'localhost'), ('::1', 'localhost'),
           ('fe80::1c2:3ff:fe44:5566', 'phone%wifi'), ('2001:db8::7', 'Printer.LAN'),
           ('192.168.1.100', 'tv_box'), ('0.0.0.0', '0.0.0.0')]
RENAMED = ('10.0.0.5', 'laptop-new')  # the name of 10.0.0.5 in the second half
UPSTREAMS = ['8.8.8.8#53', '1.1.1.1#53', '127.0.0.1#5335', '2001:db8::53#53', '9.9.9.9#9953']
FORWARDED, LISTED, CNAME_BLOCKED = {2, 6, 7, 8, 12, 13, 14, 18}, {1, 4, 5}, {9, 10, 11}


def rich_id(i):
    # IDs with gaps, as left by privacy level 3 or a flush
    return FILLER + 100 + i + i // 50 * 5


def generate(path, in_order=False):
    """Add the fixture to an empty database created by FTL. With in_order, the
    timestamps follow the IDs (ties allowed), so no timestamp is out of order"""
    rnd = random.Random(3290)

    def pick(seq):
        return seq[int(rnd.random() * len(seq))]

    # Six hours ago, well inside the 24 hours FTL imports
    t0 = int(time.time()) // 60 * 60 - 6 * 3600
    domains = {d: i for i, d in enumerate([FILLER_DOMAIN] + DOMAINS + CNAMES, 1)}
    clients = {c: i for i, c in enumerate([('192.168.1.200', 'filler')] + CLIENTS + [RENAMED], 1)}
    upstreams = {u: i for i, u in enumerate(UPSTREAMS, 1)}
    addinfo = {}

    def info(kind, content):
        return addinfo.setdefault((kind, content), len(addinfo) + 1)

    rows = [(i, t0 + i / 4, 1, 2, 1, 1, 1, None, 4, 0.0125, 0, None, -1) for i in range(1, FILLER + 1)]
    for i in range(RICH):
        # 5 s apart from three hours ago on with microseconds, some slightly
        # out of order, every 40th at the same time as the one before
        if i % 40 != 39:
            ts = t0 + 3 * 3600 + 5 * i + pick([0, 0, 0, 0.5, 2.25, -6.5]) + round(rnd.random(), 6)
            # A clock that jumps two hours ahead and back every 20 rows
            if i < 600 and not in_order:
                ts += {1: 7200, 3: -7200}.get(i // 20 % 4, 0)
            if in_order:
                ts = t0 + 3 * 3600 + 5 * i
        status = i % 19
        client = pick(CLIENTS)
        if client[0] == RENAMED[0] and i >= RICH // 2:
            client = RENAMED
        if status in LISTED | CNAME_BLOCKED:
            # Gravity and antigravity matches store -(adlist ID + 2)
            list_id = pick([None, 1, 2, 7, 15, -3, -9])
        else:
            list_id = pick([None] * 6 + [3, 4])
        if status in CNAME_BLOCKED:
            add = pick([None] + [info(1, c) for c in CNAMES])
        else:
            add = info(2, list_id) if list_id is not None else None
        rows.append((rich_id(i), ts, pick(TYPES), status, domains[pick(DOMAINS)], clients[client],
                     upstreams[pick(UPSTREAMS)] if status in FORWARDED else None, add, pick(range(14)),
                     pick([None, 0.0, 0.0005, 0.001, 0.001, 0.0123, 0.25, 1.5]), pick(range(6)), list_id,
                     pick(EDES)))
    db = sqlite3.connect(path)
    db.executemany('INSERT INTO domain_by_id VALUES (?,?)', [(i, d) for d, i in domains.items()])
    db.executemany('INSERT INTO client_by_id VALUES (?,?,?)', [(i, *c) for c, i in clients.items()])
    db.executemany('INSERT INTO forward_by_id VALUES (?,?)', [(i, u) for u, i in upstreams.items()])
    db.executemany('INSERT INTO addinfo_by_id VALUES (?,?,?)', [(i, *k) for k, i in addinfo.items()])
    db.executemany('INSERT INTO query_storage (id, timestamp, type, status, domain, client, forward, additional_info, '
                   'reply_type, reply_time, dnssec, list_id, ede) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)
    db.commit()
    db.close()


# Not compared, with the reason:
# - took: the time each answer took
# - the values of earliest_timestamp and earliest_timestamp_disk: the garbage
#   collection moves them
# - client names, unless --strict-names: the in-memory log may show the
#   current name of a client where the database has the one stored with the
#   query. Requests whose result depends on names are left out then
# recordsTotal is compared, the fixture is in memory and on disk alike
KEYS = {None: ('id',), 'time': ('time',), 'domain': ('domain',), 'client.ip': ('client', 'ip'),
        'client.name': ('client', 'name'), 'upstream': ('upstream',), 'type': ('type',),
        'status': ('status',), 'reply': ('reply', 'type'), 'reply.time': ('reply', 'time'),
        'dnssec': ('dnssec',), 'list_id': ('list_id',), 'ede': ('ede', 'code')}
FILTERS = ('domain', 'client_ip', 'client_name', 'upstream', 'type', 'status', 'reply', 'dnssec')
UI_COLUMNS = ['time', 'status', 'type', 'domain', 'client.ip', 'reply.time', '']
excludes = False
http_requests = 0
connection = None


def get(url, params, path='/api/queries'):
    global connection, http_requests
    http_requests += 1
    for attempt in range(100):
        try:
            if connection is None:
                u = urllib.parse.urlsplit(url)
                connection = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=60)
            connection.request('GET', path + '?' + urllib.parse.urlencode(params))
            r = connection.getresponse()
            return r.status, json.loads(r.read())
        except (ConnectionError, http.client.HTTPException):
            # A closed connection is opened again right away, the API may also
            # not be up yet right after the start
            connection = None
            time.sleep(0.1 if attempt else 0)
    raise RuntimeError('API not reachable at ' + url)


def sort_column(p):
    col = p.get('columns[%s][data]' % p.get('order[0][column]'), '').lower()
    ok = p.get('order[0][dir]', '').lower() in ('asc', 'ascending', 'desc', 'descending')
    return col if ok and col in KEYS else None


def fetch(url, params, disk):
    """All pages of a request, or the error it gives"""
    params = dict(params, disk='true') if disk else params
    try:
        step = int(params.get('length', 100))
    except ValueError:
        step = 100
    step = 10000 if step <= 0 or step > 10000 else step
    pages, rows, start = [], [], params.get('start', 0)
    for _ in range(300):
        status, body = get(url, dict(params, start=start))
        if status != 200:
            body.pop('took', None)
            return status, body
        page = body['queries']
        pages.append((len(page), sorted(body), body.get('draw'), body.get('cursor'), body.get('recordsTotal'),
                      body.get('recordsFiltered')))
        rows += page
        if len(page) < step:
            break
        # FTL takes a start that is no unsigned number as 0
        start = (int(start) if str(start).isdigit() else 0) + len(page)
    return pages, rows


def sort_key(row, col):
    for k in KEYS[col]:
        row = row[k]
    return row


def without_names(m, d):
    """Where memory shows no client name, the one on disk is left out: the
    in-memory log may not know it yet, but a name it shows has to match"""
    if not isinstance(m[0], list) or not isinstance(d[0], list):
        return m, d
    unnamed = {r['id'] for r in m[1] if r['client']['name'] is None}
    return m, (d[0], [dict(r, client=dict(r['client'], name=None)) if r['id'] in unnamed else r for r in d[1]])


def diff(m, d, col):
    """The first difference of memory and disk, None if there is none"""
    if not isinstance(m[0], list) or not isinstance(d[0], list):
        return None if m == d else 'memory %s, disk %s' % (str(m)[:300], str(d)[:300])
    if m[0] != d[0]:
        i = next(i for i, (a, b) in enumerate(zip(m[0] + [None], d[0] + [None])) if a != b)
        return 'page %d (rows, keys, draw, cursor, recordsTotal, recordsFiltered): memory %s, disk %s' % (
            i + 1, (m[0] + [None])[i], (d[0] + [None])[i])
    mkeys, dkeys = [sort_key(r, col) for r in m[1]], [sort_key(r, col) for r in d[1]]
    if mkeys != dkeys:
        i = next(i for i, (a, b) in enumerate(zip(mkeys, dkeys)) if a != b)
        return 'order by %s differs at row %d: memory %r, disk %r' % ('.'.join(KEYS[col]), i, mkeys[i], dkeys[i])
    # Rows with the same sort key may come in any order
    if sorted(m[1], key=lambda r: r['id']) != sorted(d[1], key=lambda r: r['id']):
        mi, di = {r['id']: r for r in m[1]}, {r['id']: r for r in d[1]}
        a, b = [r for i, r in mi.items() if di.get(i) != r], [r for i, r in di.items() if mi.get(i) != r]
        return '%d rows only in memory, %d only on disk, e.g. memory %s, disk %s' % (
            len(a), len(b), json.dumps(a[:1]), json.dumps([di.get(a[0]['id'])] if a else b[:1]))
    return None


def describe(p):
    """The parameters of a request without the DataTables boilerplate"""
    out = {k: v for k, v in p.items() if not k.startswith(('columns', 'search[', 'order'))}
    out.update({k: v for k, v in p.items() if k.endswith('[search][value]') and v})
    if 'order[0][column]' in p:
        out['order'] = '%s %s' % (p.get('columns[%s][data]' % p['order[0][column]']), p.get('order[0][dir]'))
    return urllib.parse.unquote(urllib.parse.urlencode(out))


def matrix(rows, maxid):
    """The requests, built from the data: (parameters, result depends on client names, may fail)"""
    rich = [r for r in rows if r['domain'] != FILLER_DOMAIN]
    times = sorted(r['time'] for r in rich)
    win, part = {'from': times[0], 'until': times[-1] + 1}, {'from': times[100], 'until': times[300]}
    field = {'domain': lambda r: r['domain'], 'client_ip': lambda r: r['client']['ip'],
             'upstream': lambda r: r['upstream'], 'type': lambda r: r['type'], 'status': lambda r: r['status'],
             'reply': lambda r: r['reply']['type'], 'dnssec': lambda r: r['dnssec'],
             'client_name': lambda r: r['client']['name']}
    out = []

    def add(params, names=False, window=win, invalid=False):
        p = {'cursor': maxid, **window, **params}
        out.append(({k: v for k, v in p.items() if v is not None}, names, invalid))

    def table(sort=None, direction='desc', dsearch='', csearch='', client_col='client.ip', length=25, **extra):
        # The DataTables parameters of the web interface's query log. The API
        # sorts by more columns than it shows, they take the place of the last
        cols = UI_COLUMNS[:4] + [client_col] + UI_COLUMNS[5:]
        if sort is not None and sort not in cols:
            cols[6] = sort
        p = {'draw': len(out) + 1, 'length': length, 'search[value]': '', 'search[regex]': 'false'}
        for i, c in enumerate(cols):
            p.update({'columns[%d][data]' % i: c, 'columns[%d][searchable]' % i: str(i in (3, 4)).lower(),
                      'columns[%d][orderable]' % i: str(i < 6).lower(), 'columns[%d][search][regex]' % i: 'false',
                      'columns[%d][search][value]' % i: {3: dsearch, 4: csearch}.get(i, '')})
        if sort is not None:
            p.update({'order[0][column]': cols.index(sort), 'order[0][dir]': direction})
        return {**p, **extra}

    # Every filter alone with every value in the data, wildcards and other
    # spellings, in the time window of the varied rows. Some also without
    more = {'upstream': ['blocklist', 'cache', 'permitted', UPSTREAMS[0] + ' (dns.google)', '*8.8*', '127.0.0.1*',
                         '8.8.8.8'],
            'type': ['OTHER', 'a', 'TYPE1'], 'status': ['gravity'], 'reply': ['nxdomain'], 'dnssec': ['secure'],
            'domain': ['*example*', '*.example.com', '_dmarc*', '*%*', 'a_b*', 'EXAMPLE.COM', '*EXAMPLE*',
                       'nomatch.example', 'back\\*'],
            'client_ip': ['192.168.1.*', '*::*', '*1*', '0:0:0:0:0:0:0:1', '2001:DB8::7'],
            'client_name': ['*lap*', '*', 'LAPTOP_OLD', '*_*', '*%*']}
    for f in FILTERS:
        for v in sorted({str(field[f](r)) for r in rich if field[f](r)}) + more[f]:
            add({f: v, 'length': 20}, f == 'client_name')
    for f, v in [('domain', 'hidden'), ('domain', '*example*'), ('client_ip', '10.0.0.5'), ('client_name', 'tv_box'),
                 ('client_name', '*'), ('upstream', 'cache'), ('upstream', 'permitted'), ('type', 'OTHER'),
                 ('type', 'A'), ('status', 'GRAVITY'), ('reply', 'NXDOMAIN'), ('dnssec', 'BOGUS')]:
        add({f: v, 'length': 1000}, f == 'client_name', {})
        add({f: v, 'length': 1000, 'cursor': maxid - 300}, f == 'client_name', {})
    # Pairs of filters and all of them, with the values of one row each
    for n, (a, b) in enumerate(itertools.combinations(FILTERS, 2)):
        r = next(r for r in rich[n * 23:] + rich if field[a](r) and field[b](r))
        add({a: field[a](r), b: field[b](r), 'length': 10}, 'client_name' in (a, b), {})
    for r in rich[5:400:79]:
        add({f: field[f](r) for f in FILTERS if field[f](r) and f != 'client_name'})
        add({f: field[f](r) for f in FILTERS if field[f](r)}, True, {})
    # Column searches of the web interface
    for v in ['example', 'EXAMPLE', '_', '\\_', '%', '\\%', '\\%sign', 'a_b', 'a\\_b', '*cdn*', '\\\\', 'xn--',
              'nomatch']:
        add(table(dsearch=v))
    for v in ['192.168', '::1', '10.0.0.5']:
        add(table(csearch=v))
        add(table(csearch=v, client_col='client'))
    for v in ['LAPTOP', 'lan', '_', '\\_', '%', 'host']:
        add(table(csearch=v), True)
    add(table(dsearch='example', csearch='192.168'))
    add(table(**{'columns[3][data]': 'status', 'columns[3][search][value]': 'GRAVITY'}))
    # Every sort column in both directions, other spellings, alone and with a filter
    for col in list(KEYS)[1:]:
        for d in ('asc', 'desc'):
            add(table(col, d, length=50), col == 'client.name')
        add(table(col, 'asc', length=50, cursor=maxid - 300), col == 'client.name')
    for col, d in [('domain', 'ascending'), ('reply.time', 'descending'), ('time', 'DESC'), ('status', 'Asc'),
                   ('domain', 'up'), ('nonsense', 'asc')]:
        add(table(col, d, length=50))
    add(table(**{'order[0][column]': 9, 'order[0][dir]': 'asc'}))
    add(table('time', 'asc', length=1000), window={})
    add(table('domain', 'desc', length=2000), window={})
    for col, d, f, v in [('domain', 'asc', 'status', 'GRAVITY'), ('reply.time', 'desc', 'type', 'A'),
                         ('time', 'asc', 'client_ip', '10.0.0.5'), ('upstream', 'asc', 'upstream', 'cache'),
                         ('list_id', 'desc', 'upstream', 'blocklist'), ('ede', 'asc', 'dnssec', 'BOGUS'),
                         ('type', 'desc', 'type', 'OTHER'), ('client.ip', 'asc', 'domain', '*example*')]:
        add(table(col, d, length=10, **{f: v}))
    # The first, the middle and the last pages, also of the 10000-row cap. The
    # web interface's first request comes without a cursor
    add(table('time', 'desc', cursor=None))
    for length in [None, 7, 10, 100, 500, 1000]:
        add({'length': length})
    add({'length': 7}, False, part)
    add({'length': 1, 'domain': 'hidden'})
    for length in [1000, 0, -1, 10001]:
        add({'length': length}, False, {})
    add({'length': -1, 'domain': FILLER_DOMAIN}, False, {})
    add({'length': 50, 'cursor': maxid - 123})
    add({'length': 1000, 'cursor': FILLER + 5}, False, {})
    for start in [13, 755, 5000]:
        add({'length': 25, 'start': start})
    add({'length': 1000, 'from': times[200]}, False, {})
    add({'length': 1000, 'until': times[200]}, False, {})
    # Bounds among the rows after a clock step, which are older than the rows
    # of the step before them
    row = {rich_id(i): i for i in range(RICH)}
    by_row = {row[r['id']]: r for r in rich if r['id'] in row}
    for t in [by_row[i]['time'] for i in (290, 450, 650) if i in by_row]:
        add({'length': 1000, 'from': t}, False, {})
        add({'length': 1000, 'until': t}, False, {})
    # Invalid parameters, some are ignored
    for p in [{'type': 'FOO'}, {'type': 'TYPE70000'}, {'type': 'TYPE'}, {'type': 'TYPE1x'}, {'type': 'NONE'},
              {'status': 'FOO'}, {'status': 'INVALID'}, {'reply': 'FOO'}, {'reply': 'N/A'}, {'dnssec': 'FOO'},
              {'cursor': 'abc'}, {'cursor': -1}, {'cursor': maxid + 1000}, {'from': 'abc', 'length': 1000},
              {'until': ''}, {'length': 'abc'}, {'draw': 'abc'}, {'start': -1, 'length': 1000},
              {'start': 'abc', 'length': 1000}]:
        add(p, invalid=True)
    return out


def compare(url, strict_names):
    begin = time.time()
    pages, base = fetch(url, {'length': 10000}, True)
    maxid = rich_id(RICH - 1)
    # All rows of the fixture and nothing newer, fewer with the exclusion regexes
    if (not isinstance(pages, list) or pages[0][3] != maxid or
            (len(base) >= FILLER + RICH if excludes else len(base) != FILLER + RICH)):
        print('Expected the fixture, found: %s' % (str(base)[:300] if not isinstance(pages, list) else
                                                   '%d queries up to ID %s' % (len(base), pages[0][3])))
        return 1
    failed, names_differ, total, skipped = 0, 0, 0, 0
    for params, by_name, invalid in matrix(base, maxid):
        if by_name and not strict_names:
            skipped += 1
            continue
        total += 1
        m, d = fetch(url, params, False), fetch(url, params, True)
        # A client without a name has null, never ""
        if isinstance(m[0], list) and any(r['client']['name'] == '' for r in m[1]):
            failed += 1
            print('FAILED: %s\n  an empty client name in memory' % describe(params))
            continue
        col = sort_column(params)
        full = diff(m, d, col)
        query = describe(params)
        if full is None and not invalid and not isinstance(d[0], list):
            failed += 1
            print('FAILED: %s\n  both give %s' % (query, str(d)[:300]))
            continue
        if full is None:
            continue
        unnamed = None if strict_names else diff(*without_names(m, d), col)
        if not strict_names and unnamed is None:
            names_differ += 1
        else:
            failed += 1
            print('FAILED: %s\n  %s' % (query, unnamed or full))
    names = '' if strict_names else ', %d differ in client names only, %d left out that depend on names' % (
        names_differ, skipped)
    print('%d requests (%d HTTP requests) in %.1f s%s: %d failed%s' % (
        total, http_requests, time.time() - begin, ' with exclusion regexes' if excludes else '', failed, names))
    return 1 if failed else 0


def check_paging(url, strict_names):
    """Pages of the query log in memory sorted by status and by reply type: equal
    keys come in ID order in the direction of the sort, also where pages are
    read from the other end, so every query shows up exactly once"""
    status, body = get(url, {}, '/api/queries/suggestions')
    pages, rows = fetch(url, {'length': 10000}, True)
    if status != 200 or not isinstance(pages, list):
        print('Paging: no suggestions or no queries')
        return 1
    ranks = body['suggestions']
    checked, failed = check_pages(url, rows, strict_names)
    for col, field in (('status', lambda r: r['status']), ('reply', lambda r: r['reply']['type'])):
        for direction in ('asc', 'desc'):
            ids = [r['id'] for r in sorted(rows, key=lambda r: (ranks[col].index(field(r)), r['id']),
                                           reverse=direction == 'desc')]
            for length in (10, 100, 1000, len(ids) // 2, 7000):
                starts = range(0, len(ids), length)
                if len(starts) > 30:
                    # The first pages, the middle and the last thousand rows
                    starts = [s for s in starts if s < 2 * length or abs(s - len(ids) // 2) <= length or
                              s >= len(ids) - 1000]
                for start in starts:
                    params = {'columns[0][data]': col, 'order[0][column]': 0, 'order[0][dir]': direction,
                              'length': length, 'start': start, 'cursor': rows[0]['id']}
                    status, body = get(url, params)
                    checked += 1
                    if status != 200 or [r['id'] for r in body['queries']] != ids[start:start + length]:
                        failed += 1
                        print('FAILED: paging by %s %s, %d rows from %d' % (col, direction, length, start))
    print('%d pages, single ones and by status and by reply type: %d failed' % (checked, failed))
    return 1 if failed else 0


def check_pages(url, rows, strict_names):
    """Single pages of sorted results with and without a filter and with older
    cursors: at the end, past it, in the middle and where they are read from
    the other end (start + length above 10000). Each is exactly its slice of
    the order by key and ID, with the counts of the whole result"""
    checked = failed = 0
    maxid = rows[0]['id']
    for f, cursor in (({}, maxid), ({}, maxid - 300), ({'domain': FILLER_DOMAIN}, maxid),
                      ({'upstream': 'permitted'}, FILLER + 7)):
        first, d_rows = fetch(url, dict(f, cursor=cursor, length=10000), True)
        n = len(d_rows)
        for col in ('time', 'domain', 'list_id'):
            for direction in ('asc', 'desc'):
                want = sorted(d_rows, key=lambda r: (sort_key(r, col) is not None, sort_key(r, col), r['id']),
                              reverse=direction == 'desc')
                for start in sorted({n - 1, n, n + 3, n // 2 + 7, 9990}):
                    params = dict(f, cursor=cursor, start=start, length=100, **{
                        'columns[0][data]': col, 'order[0][column]': 0, 'order[0][dir]': direction})
                    status, body = get(url, params)
                    checked += 1
                    got, exp = (body['queries'] if status == 200 else None), want[start:start + 100]
                    if got is not None and not strict_names:
                        exp = without_names(([], got), ([], exp))[1][1]
                    counts = (body.get('cursor'), body.get('recordsTotal'), body.get('recordsFiltered'))
                    if got != exp or counts != first[0][3:]:
                        failed += 1
                        print('FAILED: %s: %s rows from ID %s, expected %d from ID %s, counts %s, expected %s' % (
                            describe(params), len(got) if got is not None else status,
                            got[0]['id'] if got else None, len(exp), exp[0]['id'] if exp else None, counts,
                            first[0][3:]))
    return checked, failed


def one_page(url, params, disk):
    """A single page of a request in the form fetch() gives"""
    status, body = get(url, dict(params, disk='true') if disk else params)
    if status != 200:
        body.pop('took', None)
        return status, body
    return [(len(body['queries']), sorted(body), body.get('draw'), body.get('cursor'), body.get('recordsTotal'),
             body.get('recordsFiltered'))], body['queries']


def check_time_order(url):
    """With every timestamp in ID order, the time order is read straight off the
    queries array: single pages in both directions, with and without filters"""
    pages, rows = fetch(url, {'length': 10000}, True)
    times = sorted(r['time'] for r in rows)
    failed = total = 0
    for direction in ('asc', 'desc'):
        for p in ({}, {'start': 5000}, {'start': len(rows) - 10}, {'from': times[200]},
                  {'until': times[-200], 'start': 300}, {'domain': FILLER_DOMAIN, 'start': 9990}):
            p = dict(p, length=100, cursor=pages[0][3], **{'columns[0][data]': 'time', 'order[0][column]': 0,
                                                           'order[0][dir]': direction})
            total += 1
            res = diff(*without_names(one_page(url, p, False), one_page(url, p, True)), 'time')
            if res is not None:
                failed += 1
                print('FAILED: in ID order, %s\n  %s' % (describe(p), res))
    print('%d requests in time order without disorder: %d failed' % (total, failed))
    return 1 if failed else 0


LIVE_NAMES = ['local-a.lan', 'local-b.lan', 'gravity.ftl', 'denied.ftl', 'regex5.ftl', 'regexA.ftl', 'allowed.ftl',
              'x.slow.example', 'gravity-aaaa.ftl', 'cname.slow.example']


def live_requests(since, cursor):
    def srt(col, d):
        return {'columns[0][data]': col, 'order[0][column]': 0, 'order[0][dir]': d}
    reqs = [{}, {'domain': 'hidden'}, {'client_ip': '0.0.0.0'}, {'domain': 'gravity.ftl'},
            {'upstream': 'blocklist'}, {'upstream': 'permitted'}, {'upstream': '127.0.0.1#5398'},
            {'columns[3][data]': 'domain', 'columns[3][search][value]': 'hid'},
            {'columns[4][data]': 'client.ip', 'columns[4][search][value]': '0.0.0'}]
    reqs += [srt(c, d) for c in ('domain', 'client.ip', 'reply.time', 'list_id', 'status', 'upstream')
             for d in ('asc', 'desc')]
    return [dict(p, length=1000, cursor=cursor, **{'from': since}) for p in reqs]


def check_live(url, dns_port, path):
    """Queries sent now, at the privacy level FTL runs at: blocked by the test
    gravity database, answered locally, or forwarded to upstream(). Their rows
    in memory go to <path>, most of them before they are stored, stored()
    compares them with the database after FTL stored them on exit"""
    import socket
    import dns.exception
    import dns.message
    import dns.query
    since = time.time() - 1
    rnd = random.Random(3291)
    socks = {}
    sent = 0
    # Right after the in-memory database took the queries of this second, so
    # that most rows below are read before their queries are stored
    time.sleep(1.15 - time.time() % 1)
    for i in range(240):
        client = rnd.choice(['127.0.0.1', '127.0.0.2', '::1'])
        dest = '::1' if ':' in client else '127.0.0.1'
        try:
            if i % 12 == 0:
                # Some over TCP (forked workers), local names only
                dns.query.tcp(dns.message.make_query(LIVE_NAMES[i // 12 % 2], 'A'), dest, port=dns_port, timeout=2,
                              source=client)
            else:
                name = rnd.choice(LIVE_NAMES)
                # A name of its own for each query the upstream answers: one
                # identical to a query in flight gets the answer as a
                # duplicate, which FTL logs as an unknown reply
                if name == 'cname.slow.example':
                    name = 'q%d.cname.slow.example' % i
                q = dns.message.make_query(name, rnd.choice(['A', 'AAAA', 'TXT', 'TYPE65280']))
                if client not in socks:
                    socks[client] = socket.socket(socket.AF_INET6 if ':' in client else socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                    socks[client].bind((client, 0))
                socks[client].sendto(q.to_wire(), (dest, dns_port))
            sent += 1
        except (OSError, dns.exception.DNSException) as e:
            print('Live query from %s not sent: %s' % (client, e))
    # Until FTL has taken and answered all of them, the ones in flight stay so
    last = None
    for _ in range(100):
        status, body = get(url, {'length': 1000, 'from': since})
        state = sorted((r['id'], r['status'], r['reply']['type'], r['reply']['time']) for r in body['queries'])
        if state == last and len(state) >= sent:
            break
        last = state
        time.sleep(0.05)
    status, body = get(url, {'length': 1})
    cursor = body['cursor']
    answers = [(p, fetch(url, p, False)) for p in live_requests(since, cursor)]
    with open(path, 'w') as f:
        json.dump({'since': since, 'cursor': cursor, 'answers': answers}, f)
    n = len(answers[0][1][1])
    statuses = {r['status'] for r in answers[0][1][1]}
    print('%d live queries, %d sent, statuses %s' % (n, sent, ' '.join(sorted(statuses))))
    # Blocked by gravity, by a CNAME the upstream answered with, answered
    # locally and in flight: without them the comparison proves less
    missing = {'GRAVITY', 'GRAVITY_CNAME', 'CACHE'} - statuses
    if not statuses & {'FORWARDED', 'IN_PROGRESS'}:
        missing.add('FORWARDED or IN_PROGRESS')
    if missing:
        print('FAILED: no live query with status %s' % ', '.join(sorted(missing)))
    return 0 if n >= sent > 120 and not missing else 1


def check_stored(url, path):
    """The rows check_live() saved from memory against the database"""
    with open(path) as f:
        saved = json.load(f)
    failed = 0
    for p, m in saved['answers']:
        d = json.loads(json.dumps(fetch(url, p, True)))
        res = diff(*without_names(m, d), sort_column(p))
        if res is not None:
            failed += 1
            print('FAILED: live, %s\n  %s' % (describe(p), res))
    print('%d requests on live queries once stored: %d failed' % (len(saved['answers']), failed))
    return 1 if failed else 0


def upstream(port):
    """An upstream on 127.0.0.1:<port> that answers names under cname.slow.example
    with a CNAME to a blocked domain and nothing else at all. It prints ready
    once it listens"""
    import socket
    import dns.flags
    import dns.message
    import dns.name
    import dns.rrset
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(('127.0.0.1', port))
    print('ready', flush=True)
    while True:
        data, addr = u.recvfrom(4096)
        q = dns.message.from_wire(data)
        if q.question and q.question[0].name.is_subdomain(dns.name.from_text('cname.slow.example')):
            r = dns.message.make_response(q)
            r.flags |= dns.flags.RA
            r.answer.append(dns.rrset.from_text(q.question[0].name, 60, 'IN', 'CNAME', 'gravity.ftl.'))
            u.sendto(r.to_wire(), addr)


if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) in (2, 3) and args[0] == 'generate':
        generate(args[1], '--in-order' in args[2:])
    elif len(args) in (2, 3) and args[0] == 'paging':
        sys.exit(check_paging(args[1].rstrip('/'), '--strict-names' in args[2:]))
    elif len(args) == 2 and args[0] == 'time-order':
        sys.exit(check_time_order(args[1].rstrip('/')))
    elif len(args) == 4 and args[0] == 'live':
        sys.exit(check_live(args[1].rstrip('/'), int(args[2]), args[3]))
    elif len(args) == 3 and args[0] == 'stored':
        sys.exit(check_stored(args[1].rstrip('/'), args[2]))
    elif len(args) == 2 and args[0] == 'upstream':
        upstream(int(args[1]))
    elif len(args) >= 2 and args[0] == 'compare':
        excludes = '--excludes' in args[2:]
        sys.exit(compare(args[1].rstrip('/'), '--strict-names' in args[2:]))
    else:
        sys.exit('Usage: %s generate <database> [--in-order] | compare <url> [--excludes] [--strict-names] | '
                 'paging <url> [--strict-names] | time-order <url> | live <url> <DNS port> <file> | '
                 'stored <url> <file> | upstream <port>' % sys.argv[0])
