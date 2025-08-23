#!/usr/bin/env python3
"""
Fix admin user role in database
"""
import MySQLdb
import os
from dotenv import load_dotenv

load_dotenv()

try:
    conn = MySQLdb.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        passwd=os.getenv("DB_PASS"),
        db=os.getenv("DB_NAME"),
    )
    
    cur = conn.cursor()
    
    print("=== Current Users ===")
    cur.execute("SELECT id, username, email, status, role FROM users")
    users = cur.fetchall()
    
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Status: {user[3]}, Role: {user[4]}")
    
    print("\n=== Updating 'admin' user to have admin role ===")
    cur.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
    affected = cur.rowcount
    conn.commit()
    
    if affected > 0:
        print(f"✅ Updated {affected} user(s) to admin role")
    else:
        print("❌ No user with username 'admin' found")
        print("Creating new admin user...")
        cur.execute("""
            INSERT INTO users (username, email, password_hash, status, role) 
            VALUES ('admin', 'admin@example.com', 'admin123', 'active', 'admin')
        """)
        conn.commit()
        print("✅ Admin user created: username='admin', password='admin123'")
    
    print("\n=== Updated Users ===")
    cur.execute("SELECT id, username, email, status, role FROM users")
    users = cur.fetchall()
    
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Status: {user[3]}, Role: {user[4]}")
    
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")
    print("\nMake sure your database and tables exist!")
    print("You might need to install mysqlclient: pip install mysqlclient")