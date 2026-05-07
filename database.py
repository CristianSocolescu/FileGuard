import sqlite3

def init_db():
    #initialise database and crate the table if it doesnt exist already
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   filename TEXT UNIQUE,
                   detected_type TEXT,
                   is_suspicious BOOLEAN,
                   vt_found BOOLEAN,
                   vt_malicious INTEGER,
                   vt_suspicious INTEGER,
                   vt_error TEXT,
                   timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def save_scan_result(filename, detected_type, is_suspicious, vt_found, vt_malicious, vt_suspicious, vt_error):
    conn = sqlite3.connect ('security_logs.db')
    cursor = conn.cursor()
    cursor.execute('''
                   INSERT OR IGNORE INTO file_scans(filename, detected_type, is_suspicious, vt_found, vt_malicious, vt_suspicious, vt_error) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)''', (filename, detected_type, is_suspicious, vt_found, vt_malicious, vt_suspicious, vt_error))
    conn.commit()
    conn.close()