# 05 - Network and Browser Forensics

## PCAP Analysis
Network packets contain absolute proof of communication. Analysis typically involves Wireshark or `tshark`.

- Filter for HTTP POST requests: `http.request.method == "POST"`
- Filter for specific IPs: `ip.addr == 192.168.1.100`

## Browser Forensics
Modern browsers store history, cookies, and downloads in SQLite databases.
- **Chrome:** `C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Default\History`
- **Firefox:** `C:\Users\<User>\AppData\Roaming\Mozilla\Firefox\Profiles\<Profile>\places.sqlite`

### Analyzing SQLite with Python
```python
import sqlite3
import pandas as pd

def read_chrome_history(db_path):
    # Connect to SQLite DB
    conn = sqlite3.connect(db_path)
    
    # Query URLs visited
    query = """
    SELECT urls.url, urls.title, urls.visit_count,
    datetime(visits.visit_time / 1000000 - 11644473600, 'unixepoch', 'localtime') AS visit_time
    FROM urls
    JOIN visits ON urls.id = visits.url
    ORDER BY visit_time DESC
    LIMIT 10;
    """
    
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# Example usage (Make sure the browser is closed or operate on a copy of the DB!)
# df = read_chrome_history("History.sqlite")
# print(df)
```
