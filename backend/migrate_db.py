import sqlite3
import os

DB_PATH = 'dac.db'
if not os.path.exists(DB_PATH):
    print(f"DB not found at {DB_PATH}")
    exit(1)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute("PRAGMA table_info(sigma_rules)")
cols = [r[1] for r in c.fetchall()]

if 'rule_format' not in cols:
    print("Adding rule_format to sigma_rules")
    c.execute("ALTER TABLE sigma_rules ADD COLUMN rule_format VARCHAR(50) NOT NULL DEFAULT 'yaml'")

if 'json_content' not in cols:
    print("Adding json_content to sigma_rules")
    c.execute("ALTER TABLE sigma_rules ADD COLUMN json_content TEXT")

# Create rule_changes table
print("Creating rule_changes table")
c.execute("""
CREATE TABLE IF NOT EXISTS rule_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    rule_format VARCHAR(50) NOT NULL,
    previous_content TEXT,
    new_content TEXT NOT NULL,
    change_reason TEXT NOT NULL,
    expected_outcome TEXT,
    changed_by VARCHAR(255) NOT NULL DEFAULT 'local analyst',
    changed_at DATETIME NOT NULL,
    change_type VARCHAR(50) NOT NULL,
    FOREIGN KEY(rule_id) REFERENCES sigma_rules(id) ON DELETE CASCADE
)
""")
c.execute("CREATE INDEX IF NOT EXISTS ix_rule_changes_rule_id ON rule_changes(rule_id)")
c.execute("CREATE INDEX IF NOT EXISTS ix_rule_changes_change_type ON rule_changes(change_type)")

c.execute("PRAGMA table_info(rule_changes)")
cols_rc = [r[1] for r in c.fetchall()]
if 'parent_change_id' not in cols_rc:
    print("Adding parent_change_id to rule_changes")
    c.execute("ALTER TABLE rule_changes ADD COLUMN parent_change_id INTEGER REFERENCES rule_changes(id)")

conn.commit()
conn.close()
print("Migration completed.")
