import mysql.connector
import time

db = mysql.connector.connect(
    host="192.168.126.1",
    user="aimms",
    password="root123",
    database="aimms"
)

cursor = db.cursor()

print("Aggregator started...")

while True:

    query = """
    SELECT 
        src_ip,
        COUNT(*) as packet_count,
        SUM(length) as total_bytes,
        COUNT(DISTINCT dst_port) as unique_ports
    FROM packets
    WHERE timestamp >= NOW() - INTERVAL 1 MINUTE
    GROUP BY src_ip
    """

    cursor.execute(query)
    results = cursor.fetchall()

    insert_query = """
    INSERT INTO traffic_summary(src_ip, packet_count, total_bytes, unique_ports)
    VALUES (%s, %s, %s, %s)
    """

    for row in results:
        cursor.execute(insert_query, row)

    db.commit()

    print("Inserted aggregated data")

    time.sleep(30)
