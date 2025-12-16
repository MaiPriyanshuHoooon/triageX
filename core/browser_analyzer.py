"""
Browser History Analyzer
========================
Extracts and analyzes browser history from Chrome, Firefox, Edge, Brave, Opera
Supports forensic timeline reconstruction and activity analysis
"""

import sqlite3
import os
import shutil
import sys
from datetime import datetime, timedelta
from pathlib import Path


class BrowserHistoryAnalyzer:
    """Analyzes browser history from multiple browsers"""

    def __init__(self):
        self.CHROME_EPOCH = datetime(1601, 1, 1)  # Chrome timestamp epoch
        self.FIREFOX_EPOCH = datetime(1970, 1, 1)  # Firefox/Unix epoch

    def get_browser_paths(self):
        """Get paths to browser history databases based on OS"""
        paths = {}

        if sys.platform == 'win32':
            # Windows paths
            appdata = os.environ.get('LOCALAPPDATA', '')
            roaming = os.environ.get('APPDATA', '')

            paths = {
                'Chrome': os.path.join(appdata, 'Google', 'Chrome', 'User Data', 'Default', 'History'),
                'Edge': os.path.join(appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'History'),
                'Brave': os.path.join(appdata, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'History'),
                'Opera': os.path.join(roaming, 'Opera Software', 'Opera Stable', 'History'),
                'Firefox': self._find_firefox_profile(roaming)
            }

        elif sys.platform == 'darwin':
            # macOS paths
            home = os.path.expanduser('~')
            paths = {
                'Chrome': os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'History'),
                'Edge': os.path.join(home, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'History'),
                'Brave': os.path.join(home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Default', 'History'),
                'Opera': os.path.join(home, 'Library', 'Application Support', 'com.operasoftware.Opera', 'History'),
                'Safari': os.path.join(home, 'Library', 'Safari', 'History.db'),
                'Firefox': self._find_firefox_profile(os.path.join(home, 'Library', 'Application Support', 'Firefox'))
            }

        elif sys.platform.startswith('linux'):
            # Linux paths
            home = os.path.expanduser('~')
            paths = {
                'Chrome': os.path.join(home, '.config', 'google-chrome', 'Default', 'History'),
                'Chromium': os.path.join(home, '.config', 'chromium', 'Default', 'History'),
                'Brave': os.path.join(home, '.config', 'BraveSoftware', 'Brave-Browser', 'Default', 'History'),
                'Opera': os.path.join(home, '.config', 'opera', 'History'),
                'Firefox': self._find_firefox_profile(os.path.join(home, '.mozilla', 'firefox'))
            }

        return paths

    def _find_firefox_profile(self, firefox_base):
        """Find Firefox profile directory (it has random characters)"""
        if not os.path.exists(firefox_base):
            return None

        # Look for profiles.ini or scan for *.default directory
        profiles_dir = os.path.join(firefox_base, 'Profiles')
        if os.path.exists(profiles_dir):
            for profile in os.listdir(profiles_dir):
                if profile.endswith('.default') or profile.endswith('.default-release'):
                    places_db = os.path.join(profiles_dir, profile, 'places.sqlite')
                    if os.path.exists(places_db):
                        return places_db
        return None

    def extract_chrome_history(self, db_path, limit=None, days_back=365):
        """
        Extract history from Chrome/Edge/Brave (Chromium-based browsers)

        Args:
            db_path: Path to browser History database
            limit: Maximum number of entries (None = unlimited)
            days_back: Number of days to look back (default 365 = 1 year)
        """
        if not os.path.exists(db_path):
            return []

        # Copy database to temp location (browser locks it)
        temp_db = f"temp_history_{os.getpid()}.db"
        try:
            shutil.copy2(db_path, temp_db)
        except Exception as e:
            print(f"    ⚠️  Failed to copy database: {e}")
            return []

        results = []

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Calculate cutoff date (days_back from now)
            cutoff_date = datetime.now() - timedelta(days=days_back)
            # Convert to Chrome timestamp (microseconds since 1601-01-01)
            cutoff_chrome_time = int((cutoff_date - self.CHROME_EPOCH).total_seconds() * 1000000)

            # Query ONLY urls table to avoid duplicate entries from multiple visits
            # The urls table already has aggregated visit_count, so we don't need the visits join
            query = """
            SELECT
                url,
                title,
                visit_count,
                typed_count,
                last_visit_time,
                hidden
            FROM urls
            WHERE last_visit_time >= ?
            ORDER BY last_visit_time DESC
            """

            if limit:
                query += " LIMIT ?"
                cursor.execute(query, (cutoff_chrome_time, limit))
            else:
                cursor.execute(query, (cutoff_chrome_time,))

            for row in cursor.fetchall():
                url, title, visit_count, typed_count, last_visit, hidden = row

                # Since we're not joining visits table, we don't have individual visit data
                # Use last_visit_time for both timestamps and set a generic visit type
                visit_time = last_visit
                transition = typed_count  # Use typed_count as indicator for visit type

                # Convert Chrome timestamp (microseconds since 1601-01-01)
                if last_visit:
                    try:
                        last_visit_dt = self.CHROME_EPOCH + timedelta(microseconds=last_visit)
                    except:
                        last_visit_dt = "Unknown"
                else:
                    last_visit_dt = "Unknown"

                # Convert visit_time if available
                if visit_time:
                    try:
                        visit_time_dt = self.CHROME_EPOCH + timedelta(microseconds=visit_time)
                    except:
                        visit_time_dt = last_visit_dt
                else:
                    visit_time_dt = last_visit_dt

                # Determine visit type based on transition
                visit_type = self._get_transition_type(transition)

                results.append({
                    'url': url or '',
                    'title': title or 'No Title',
                    'visit_count': visit_count or 0,
                    'typed_count': typed_count or 0,
                    'last_visit': str(last_visit_dt),
                    'visit_time': str(visit_time_dt),
                    'hidden': bool(hidden),
                    'visit_type': visit_type
                })

            conn.close()

        except Exception as e:
            print(f"Error extracting Chrome history: {e}")

        finally:
            # Cleanup temp database
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except:
                    pass

        return results

    def extract_firefox_history(self, db_path, limit=None, days_back=365):
        """
        Extract history from Firefox

        Args:
            db_path: Path to Firefox places.sqlite database
            limit: Maximum number of entries (None = unlimited)
            days_back: Number of days to look back (default 365 = 1 year)
        """
        if not db_path or not os.path.exists(db_path):
            return []

        # Copy database to temp location
        temp_db = f"temp_firefox_{os.getpid()}.db"
        try:
            shutil.copy2(db_path, temp_db)
        except Exception as e:
            print(f"    ⚠️  Failed to copy Firefox database: {e}")
            return []

        results = []

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Calculate cutoff date for Firefox (microseconds since Unix epoch)
            cutoff_date = datetime.now() - timedelta(days=days_back)
            cutoff_firefox_time = int((cutoff_date - self.FIREFOX_EPOCH).total_seconds() * 1000000)

            # Query ONLY moz_places table to avoid duplicate entries from multiple visits
            # The moz_places table already has aggregated visit_count
            query = """
            SELECT
                url,
                title,
                visit_count,
                typed,
                last_visit_date,
                hidden
            FROM moz_places
            WHERE last_visit_date >= ?
            ORDER BY last_visit_date DESC
            """

            if limit:
                query += " LIMIT ?"
                cursor.execute(query, (cutoff_firefox_time, limit))
            else:
                cursor.execute(query, (cutoff_firefox_time,))

            for row in cursor.fetchall():
                url, title, visit_count, typed, last_visit, hidden = row

                # Since we're not joining historyvisits, use last_visit for both timestamps
                visit_date = last_visit
                visit_type = 1 if typed else 0  # Generic visit type based on typed status

                # Convert Firefox timestamp (microseconds since Unix epoch)
                if last_visit:
                    try:
                        last_visit_dt = self.FIREFOX_EPOCH + timedelta(microseconds=last_visit)
                    except:
                        last_visit_dt = "Unknown"
                else:
                    last_visit_dt = "Unknown"

                if visit_date:
                    try:
                        visit_date_dt = self.FIREFOX_EPOCH + timedelta(microseconds=visit_date)
                    except:
                        visit_date_dt = last_visit_dt
                else:
                    visit_date_dt = last_visit_dt

                # Firefox visit types
                ff_visit_type = self._get_firefox_visit_type(visit_type)

                results.append({
                    'url': url or '',
                    'title': title or 'No Title',
                    'visit_count': visit_count or 0,
                    'typed_count': typed or 0,
                    'last_visit': str(last_visit_dt),
                    'visit_time': str(visit_date_dt),
                    'hidden': bool(hidden),
                    'visit_type': ff_visit_type
                })

            conn.close()

        except Exception as e:
            print(f"Error extracting Firefox history: {e}")

        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except:
                    pass

        return results

    def _get_transition_type(self, transition):
        """Decode Chrome transition type"""
        if transition is None:
            return "Unknown"

        # Chrome transition types (bitmask)
        core_type = transition & 0xFF

        types = {
            0: "Link Click",
            1: "Typed URL",
            2: "Auto Bookmark",
            3: "Auto Subframe",
            4: "Manual Subframe",
            5: "Generated",
            6: "Auto Toplevel",
            7: "Form Submit",
            8: "Reload",
            9: "Keyword",
            10: "Keyword Generated"
        }

        return types.get(core_type, f"Unknown ({core_type})")

    def _get_firefox_visit_type(self, visit_type):
        """Decode Firefox visit type"""
        if visit_type is None:
            return "Unknown"

        types = {
            1: "Link",
            2: "Typed",
            3: "Bookmark",
            4: "Embed",
            5: "Redirect Permanent",
            6: "Redirect Temporary",
            7: "Download",
            8: "Framed Link",
            9: "Reload"
        }

        return types.get(visit_type, f"Unknown ({visit_type})")

    def extract_safari_history(self, db_path, limit=None, days_back=365):
        """
        Extract history from Safari (macOS only)

        Args:
            db_path: Path to Safari History.db
            limit: Maximum number of entries (None = unlimited)
            days_back: Number of days to look back (default 365 = 1 year)

        Note: Requires Full Disk Access permission on macOS
        """
        if not db_path or not os.path.exists(db_path):
            return []

        # Copy database to temp location
        temp_db = f"temp_safari_{os.getpid()}.db"
        try:
            shutil.copy2(db_path, temp_db)
        except PermissionError:
            print(f"    ⚠️  Safari: Permission Denied")
            print(f"       💡 Solution: Grant Terminal 'Full Disk Access' in System Preferences")
            print(f"          Go to: System Preferences → Security & Privacy → Privacy → Full Disk Access")
            print(f"          Add: Terminal.app (or your terminal application)")
            return []
        except Exception as e:
            print(f"    ⚠️  Failed to access Safari database: {e}")
            return []

        results = []

        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Calculate cutoff date (Safari uses Unix timestamp with CoreFoundation offset)
            cutoff_date = datetime.now() - timedelta(days=days_back)
            # Safari uses Core Foundation timestamp (seconds since 2001-01-01)
            safari_epoch = datetime(2001, 1, 1)
            cutoff_safari_time = (cutoff_date - safari_epoch).total_seconds()

            # Safari schema: history_items and history_visits
            query = """
            SELECT
                history_items.url,
                history_items.domain_expansion,
                history_items.visit_count,
                history_visits.visit_time,
                history_visits.title
            FROM history_items
            LEFT JOIN history_visits ON history_items.id = history_visits.history_item
            WHERE history_visits.visit_time >= ?
            ORDER BY history_visits.visit_time DESC
            """

            if limit:
                query += " LIMIT ?"
                cursor.execute(query, (cutoff_safari_time, limit))
            else:
                cursor.execute(query, (cutoff_safari_time,))

            safari_epoch_dt = datetime(2001, 1, 1)

            for row in cursor.fetchall():
                url, domain, visit_count, visit_time, title = row

                # Convert Safari timestamp (seconds since 2001-01-01)
                if visit_time:
                    try:
                        visit_time_dt = safari_epoch_dt + timedelta(seconds=visit_time)
                    except:
                        visit_time_dt = "Unknown"
                else:
                    visit_time_dt = "Unknown"

                results.append({
                    'url': url or '',
                    'title': title or domain or 'No Title',
                    'visit_count': visit_count or 0,
                    'typed_count': 0,  # Safari doesn't track this
                    'last_visit': str(visit_time_dt),
                    'visit_time': str(visit_time_dt),
                    'hidden': False,
                    'visit_type': "Safari Visit"
                })

            conn.close()

        except Exception as e:
            print(f"    ⚠️  Error extracting Safari history: {e}")

        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except:
                    pass

        return results

    def analyze_all_browsers(self, limit=None, days_back=365):
        """
        Analyze history from all installed browsers

        Args:
            limit: Maximum entries per browser (None = unlimited, gets ALL history)
            days_back: How many days back to retrieve (default 365 = 1 year)

        Returns:
            Dictionary with browser names as keys and history lists as values
        """
        all_history = {}
        paths = self.get_browser_paths()

        print(f"[+] 🌐 Analyzing Browser History (Last {days_back} days)...")
        if limit:
            print(f"    📊 Limiting to {limit} entries per browser")
        else:
            print(f"    📊 Retrieving ALL available history (no limit)")

        for browser, db_path in paths.items():
            if not db_path:
                continue

            if not os.path.exists(db_path):
                print(f"    └─ {browser}: Not installed")
                continue

            print(f"    └─ Extracting {browser} history...")

            try:
                if browser == 'Firefox':
                    history = self.extract_firefox_history(db_path, limit, days_back)
                elif browser == 'Safari':
                    history = self.extract_safari_history(db_path, limit, days_back)
                else:
                    # Chrome, Edge, Brave, Opera (all Chromium-based)
                    history = self.extract_chrome_history(db_path, limit, days_back)

                if history:
                    all_history[browser] = history
                    print(f"       ✅ Found {len(history)} entries")
                else:
                    print(f"       ⚠️  No history found in date range")

            except Exception as e:
                print(f"       ❌ Error: {e}")

        print(f"    ✅ Completed browser analysis: {len(all_history)} browsers with data\n")
        return all_history

    def _extract_domain(self, url):
        """Extract base domain from URL (removes redundant paths/routes)"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)

            # Get domain without www
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]

            # For localhost, include port
            if 'localhost' in domain or '127.0.0.1' in domain:
                return f"{parsed.scheme}://{parsed.netloc}"

            # Return just the domain
            return domain if domain else url
        except:
            return url

    def get_statistics(self, history_data):
        """Generate statistics from browser history - groups by domain to remove redundancy"""
        stats = {
            'total_entries': 0,
            'browsers_found': 0,
            'most_visited': [],
            'most_visited_domains': [],  # NEW: Domain-grouped stats
            'total_visits': 0
        }

        all_urls = {}
        all_domains = {}  # NEW: Track visits by domain

        for browser, entries in history_data.items():
            stats['browsers_found'] += 1
            stats['total_entries'] += len(entries)

            for entry in entries:
                url = entry.get('url', '')
                visit_count = entry.get('visit_count', 0)

                if url:
                    # Original URL tracking (for detailed view)
                    if url in all_urls:
                        all_urls[url] += visit_count
                    else:
                        all_urls[url] = visit_count

                    # NEW: Domain-based tracking (removes redundant routes)
                    domain = self._extract_domain(url)
                    if domain in all_domains:
                        all_domains[domain]['count'] += visit_count
                        all_domains[domain]['sample_url'] = url  # Keep one example URL
                    else:
                        all_domains[domain] = {
                            'count': visit_count,
                            'sample_url': url
                        }

                    stats['total_visits'] += visit_count

        # Get top 10 most visited DOMAINS (removes redundancy)
        sorted_domains = sorted(all_domains.items(), key=lambda x: x[1]['count'], reverse=True)
        stats['most_visited_domains'] = [
            {
                'domain': domain,
                'url': info['sample_url'],
                'count': info['count']
            }
            for domain, info in sorted_domains[:10]
        ]

        # Keep original URL-based stats for backward compatibility
        sorted_urls = sorted(all_urls.items(), key=lambda x: x[1], reverse=True)
        stats['most_visited'] = [{'url': url, 'count': count} for url, count in sorted_urls[:10]]

        return stats


# Standalone test function
if __name__ == "__main__":
    print("="*70)
    print("BROWSER HISTORY ANALYZER - STANDALONE TEST")
    print("="*70)

    analyzer = BrowserHistoryAnalyzer()

    # Get 1 year of history with no limit
    history = analyzer.analyze_all_browsers(limit=None, days_back=365)

    print("\n" + "="*70)
    print("BROWSER HISTORY SUMMARY")
    print("="*70)

    for browser, entries in history.items():
        print(f"\n{browser}: {len(entries)} entries")
        if entries:
            print(f"  Latest: {entries[0].get('title')}")
            print(f"  URL: {entries[0].get('url')[:80]}...")
            print(f"  Date: {entries[0].get('last_visit')}")

            # Show oldest entry too
            if len(entries) > 1:
                print(f"  Oldest: {entries[-1].get('title')}")
                print(f"  Date: {entries[-1].get('last_visit')}")

    stats = analyzer.get_statistics(history)
    print("\n" + "="*70)
    print("STATISTICS")
    print("="*70)
    print(f"Total Entries: {stats['total_entries']}")
    print(f"Total Visits: {stats['total_visits']}")
    print(f"Browsers Found: {stats['browsers_found']}")

    if stats['most_visited']:
        print("\nTop 5 Most Visited Sites:")
        for i, site in enumerate(stats['most_visited'][:5], 1):
            print(f"  {i}. {site['url'][:60]} ({site['count']} visits)")

    print("="*70)
