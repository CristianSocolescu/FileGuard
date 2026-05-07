from flask import Flask, render_template
import sqlite3
from database import init_db
from detector import analyze_directory

app = Flask(__name__)
init_db()

@app.route('/')
def index():
    analyze_directory("./to_scan")
    
    conn = sqlite3.connect('security_logs.db')
    cursor = conn.cursor()
    #take all logs to show on the dashboard
    cursor.execute("SELECT * FROM file_scans ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)