PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE queries (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT, additional_info TEXT, reply INTEGER, dnssec INTEGER, reply_time INTEGER, client_name TEXT, ttl INTEGER, regex_id INTEGER);
CREATE TABLE ftl (id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL);
INSERT INTO ftl VALUES(0,10);
INSERT INTO ftl VALUES(1,1592886836);
INSERT INTO ftl VALUES(2,1592886833);
CREATE TABLE counters (id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL);
INSERT INTO counters VALUES(0,21);
INSERT INTO counters VALUES(1,6);
CREATE TABLE message (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type TEXT NOT NULL, message TEXT NOT NULL, blob1 BLOB, blob2 BLOB, blob3 BLOB, blob4 BLOB, blob5 BLOB);
CREATE TABLE IF NOT EXISTS "network" (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL, interface TEXT NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL, macVendor TEXT, aliasclient_id INTEGER);
CREATE TABLE IF NOT EXISTS "network_addresses" (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL, lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)), name TEXT, nameUpdated INTEGER, FOREIGN KEY(network_id) REFERENCES network(id));
CREATE INDEX idx_queries_timestamps ON queries (timestamp);

INSERT INTO "network" (id, hwaddr, interface, firstSeen, lastQuery, numQueries) VALUES (0, 'aa:bb:cc:dd:ee:ff', 'lo123', 0, 0, 0);
INSERT INTO "network_addresses" (network_id, ip) VALUES (0, '127.0.0.4');
INSERT INTO "network_addresses" (network_id, ip) VALUES (0, '127.0.0.5');

INSERT INTO "network" (id, hwaddr, interface, firstSeen, lastQuery, numQueries, aliasclient_id) VALUES (1, '00:11:22:33:44:55', 'enp0s123', 0, 0, 0, 0);
INSERT INTO "network_addresses" (network_id, ip) VALUES (1, '127.0.0.6');

CREATE TABLE aliasclient (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, comment TEXT);
INSERT INTO aliasclient (id, name) VALUES (0, 'some-aliasclient');

COMMIT;
