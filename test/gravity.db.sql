PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE whitelist
(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT UNIQUE NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	date_added INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	date_modified INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	comment TEXT
);
INSERT INTO whitelist VALUES(1,'whitelisted.com',1,1559928803,1559928803,'Migrated from /etc/pihole/whitelist.txt');
CREATE TABLE blacklist
(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT UNIQUE NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	date_added INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	date_modified INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	comment TEXT
);
INSERT INTO blacklist VALUES(1,'blacklisted.com',1,1559928803,1559928803,'Migrated from /etc/pihole/blacklist.txt');
CREATE TABLE regex
(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT UNIQUE NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	date_added INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	date_modified INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	comment TEXT
);
INSERT INTO regex VALUES(1,'regex[0-9].com',1,1559928803,1559928803,'Migrated from /etc/pihole/regex.list');
CREATE TABLE adlists
(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	address TEXT UNIQUE NOT NULL,
	enabled BOOLEAN NOT NULL DEFAULT 1,
	date_added INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	date_modified INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)),
	comment TEXT
);
INSERT INTO adlists VALUES(1,'https://hosts-file.net/ad_servers.txt',1,1559928803,1559928803,'Migrated from /etc/pihole/adlists.list');
CREATE TABLE gravity
(
	domain TEXT PRIMARY KEY
);
INSERT INTO gravity VALUES('0427d7.se');
CREATE TABLE info
(
	property TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
INSERT INTO info VALUES('version','1');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('adlists',1);
INSERT INTO sqlite_sequence VALUES('blacklist',1);
INSERT INTO sqlite_sequence VALUES('whitelist',1);
INSERT INTO sqlite_sequence VALUES('regex',1);
CREATE VIEW vw_gravity AS SELECT a.domain
	FROM gravity a
	WHERE a.domain NOT IN (SELECT domain from whitelist WHERE enabled == 1);
CREATE VIEW vw_whitelist AS SELECT a.domain
	FROM whitelist a
	WHERE a.enabled == 1
	ORDER BY a.id;
CREATE TRIGGER tr_whitelist_update AFTER UPDATE ON whitelist
	BEGIN
		UPDATE whitelist SET date_modified = (cast(strftime('%s', 'now') as int)) WHERE domain = NEW.domain;
	END;
CREATE VIEW vw_blacklist AS SELECT a.domain
	FROM blacklist a
	WHERE a.enabled == 1 AND a.domain NOT IN vw_whitelist
	ORDER BY a.id;
CREATE TRIGGER tr_blacklist_update AFTER UPDATE ON blacklist
	BEGIN
		UPDATE blacklist SET date_modified = (cast(strftime('%s', 'now') as int)) WHERE domain = NEW.domain;
	END;
CREATE VIEW vw_regex AS SELECT a.domain
	FROM regex a
	WHERE a.enabled == 1
	ORDER BY a.id;
CREATE TRIGGER tr_regex_update AFTER UPDATE ON regex
	BEGIN
		UPDATE regex SET date_modified = (cast(strftime('%s', 'now') as int)) WHERE domain = NEW.domain;
	END;
CREATE VIEW vw_adlists AS SELECT a.address
	FROM adlists a
	WHERE a.enabled == 1
	ORDER BY a.id;
CREATE TRIGGER tr_adlists_update AFTER UPDATE ON adlists
	BEGIN
		UPDATE adlists SET date_modified = (cast(strftime('%s', 'now') as int)) WHERE address = NEW.address;
	END;
COMMIT;
