import sqlite3
conn = sqlite3.connect("/opt/S4A21Server/publish/Data/inventory.db")
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM characters WHERE delete_flag = 0")
print("Alive characters:", cur.fetchone()[0])
cur.execute("SELECT character_id, account_id, name FROM characters WHERE delete_flag = 0 LIMIT 5")
for row in cur.fetchall():
    print(row)
