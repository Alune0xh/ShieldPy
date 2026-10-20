import sqlite3
from datetime import datetime, timedelta


def get_scan_stats(db_path, user_id, user_role, days=7):
    date_list = [] # for only last 7 days
    for i in range(days - 1, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime("%b %d")
        date_list.append(day)

    daily_counts = {}
    for day in date_list:
        daily_counts[day] = 0

    status_breakdown = {}

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if user_role == "admin":
        cursor.execute("SELECT status, scanned_at FROM scanned_files")
    else:
        cursor.execute("SELECT status, scanned_at FROM scanned_files WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()

    cutoff = datetime.now() - timedelta(days=days)
    for status, scanned_at in rows:
        try:
            date_obj = datetime.strptime(scanned_at, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            continue  

        if date_obj < cutoff:
            continue

        if status not in status_breakdown:
            status_breakdown[status] = 0
        status_breakdown[status] += 1

        day_key = date_obj.strftime("%b %d")
        if day_key in daily_counts:
            daily_counts[day_key] += 1

    conn.close()
    return {"status_breakdown": status_breakdown, "daily_counts": daily_counts, "date_list": date_list}


def get_summary_counts(db_path, user_id, user_role, days=7):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S") 
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    if user_role == "admin":
        user_filter = ""
        extra_params = ()
    else:
        user_filter = " AND user_id = ?"
        extra_params = (user_id,)

    scanned = cursor.execute(
        f"SELECT COUNT(*) FROM scanned_files WHERE scanned_at >= ?{user_filter}",
        (cutoff,) + extra_params
    ).fetchone()[0]

    threats = cursor.execute(
        f"SELECT COUNT(*) FROM scanned_files WHERE scanned_at >= ? AND status IN ('dangerous','fatal','suspicious'){user_filter}",
        (cutoff,) + extra_params
    ).fetchone()[0]

    deleted = cursor.execute(
        f"SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ? AND action = 'file got deleted'{user_filter}",
        (cutoff,) + extra_params
    ).fetchone()[0]

    restored = cursor.execute(
        f"SELECT COUNT(*) FROM audit_logs WHERE timestamp >= ? AND action = 'file got restored'{user_filter}",
        (cutoff,) + extra_params
    ).fetchone()[0]

    conn.close()
    return {"threats": threats, "scanned": scanned, "deleted": deleted, "restored": restored}