"""Export helpers — PDF & CSV generation for HoursLog."""

import io
import csv
import base64
from datetime import date, timedelta, datetime

from flask import current_app
from sqlalchemy import func

from app import db
from app.models import LogEntry, Category, Role, User


# ── Date-range filtering ──────────────────────────────────────────────────

def resolve_date_range(period, start_str=None, end_str=None):
    """Return (start_date, end_date) or (None, None) for 'all'.

    Supported *period* values: all, week, month, year, custom.
    For 'custom', *start_str* / *end_str* should be ISO-format date strings.
    """
    today = date.today()
    if period == 'week':
        return today - timedelta(days=today.weekday()), today
    elif period == 'month':
        return today.replace(day=1), today
    elif period == 'year':
        return today.replace(month=1, day=1), today
    elif period == 'custom':
        try:
            sd = datetime.strptime(start_str, '%Y-%m-%d').date() if start_str else None
            ed = datetime.strptime(end_str, '%Y-%m-%d').date() if end_str else None
            return sd, ed
        except (ValueError, TypeError):
            return None, None
    # 'all' or unrecognised → no filter
    return None, None


def query_entries(user_id, start_date=None, end_date=None):
    """Return a list of LogEntry objects filtered by user & optional dates."""
    q = LogEntry.query.filter_by(user_id=user_id).order_by(LogEntry.date.desc())
    if start_date:
        q = q.filter(LogEntry.date >= start_date)
    if end_date:
        q = q.filter(LogEntry.date <= end_date)
    return q.all()


def compute_summary(entries):
    """Compute summary stats from a list of LogEntry objects.

    Returns dict with keys: total_hours, activity_hours, travel_hours,
    total_entries, hours_by_category, hours_by_role.
    """
    total_entries = len(entries)
    activity_hours = sum(e.hours for e in entries)
    travel_hours = sum(e.travel_hours or 0 for e in entries)
    total_hours = activity_hours + travel_hours

    cat_map = {}
    for e in entries:
        name = e.category.name
        color = e.category.color
        cat_map.setdefault(name, {'hours': 0, 'color': color})
        cat_map[name]['hours'] += e.total_hours

    role_map = {}
    for e in entries:
        name = e.role.name
        role_map[name] = role_map.get(name, 0) + e.total_hours

    return {
        'total_hours': total_hours,
        'activity_hours': activity_hours,
        'travel_hours': travel_hours,
        'total_entries': total_entries,
        'hours_by_category': cat_map,   # {name: {hours, color}}
        'hours_by_role': role_map,       # {name: hours}
    }


# ── Chart generation (matplotlib) ─────────────────────────────────────────

def _try_import_matplotlib():
    """Import matplotlib with Agg backend; returns (plt, True) or (None, False)."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        return plt, True
    except ImportError:
        return None, False


def generate_category_chart_b64(summary):
    """Return a base64-encoded PNG of a doughnut chart for hours by category."""
    plt, ok = _try_import_matplotlib()
    if not ok or not summary['hours_by_category']:
        return None

    labels = list(summary['hours_by_category'].keys())
    sizes = [summary['hours_by_category'][l]['hours'] for l in labels]
    colors = [summary['hours_by_category'][l]['color'] for l in labels]

    fig, ax = plt.subplots(figsize=(4, 4))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, autopct='%1.1f%%', startangle=90,
        colors=colors, pctdistance=0.75,
    )
    centre_circle = plt.Circle((0, 0), 0.55, fc='white')
    ax.add_artist(centre_circle)
    ax.set_title('Hours by Category', fontsize=13, fontweight='bold')
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('ascii')


def generate_role_chart_b64(summary):
    """Return a base64-encoded PNG of a bar chart for hours by role."""
    plt, ok = _try_import_matplotlib()
    if not ok or not summary['hours_by_role']:
        return None

    labels = list(summary['hours_by_role'].keys())
    values = [summary['hours_by_role'][l] for l in labels]

    fig, ax = plt.subplots(figsize=(5, 3.5))
    bars = ax.barh(labels, values, color='#3698eb')
    ax.set_xlabel('Hours')
    ax.set_title('Hours by Role', fontsize=13, fontweight='bold')
    ax.invert_yaxis()
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                f'{val:.1f}', va='center', fontsize=9)
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('ascii')


# ── CSV generation ─────────────────────────────────────────────────────────

def generate_csv(entries, user_display_name=''):
    """Return a UTF-8 CSV string of log entries."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Date', 'Title', 'Category', 'Primary Role', 'Secondary Roles',
        'Activity Hours', 'Travel Hours', 'Total Hours', 'Description', 'Notes',
    ])
    for e in entries:
        secondary = ', '.join(r.name for r in e.secondary_roles)
        writer.writerow([
            e.date.strftime('%Y-%m-%d'),
            e.title,
            e.category.name,
            e.role.name,
            secondary,
            f'{e.hours:.2f}',
            f'{(e.travel_hours or 0):.2f}',
            f'{e.total_hours:.2f}',
            e.description or '',
            e.notes or '',
        ])
    return output.getvalue()


# ── PDF generation (xhtml2pdf) ─────────────────────────────────────────────

def generate_pdf(html_string):
    """Convert an HTML string to PDF bytes using xhtml2pdf.

    Returns bytes on success, or None if xhtml2pdf is not installed.
    """
    try:
        from xhtml2pdf import pisa
        result_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(io.StringIO(html_string), dest=result_buffer)
        if pisa_status.err:
            return None
        return result_buffer.getvalue()
    except ImportError:
        return None
