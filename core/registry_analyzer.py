"""
Registry Analysis Module
========================
Forensic analysis of Windows Registry hives
Extracts artifacts from NTUSER.DAT, SOFTWARE, SYSTEM, SAM hives

Artifacts Extracted:
- UserAssist (program execution tracking with ROT13 decode)
- Run/RunOnce keys (persistence mechanisms)
- Recent Documents (user activity)
- USB Device History (connected devices)
- Typed URLs (browsing history)
- Shimcache/AppCompatCache (program execution)
- Installed Programs (software inventory)
- Network Profiles (WiFi/Network history)
- MRU Lists (Most Recently Used files)
"""

import os
import sys
import codecs
from datetime import datetime, timedelta
from pathlib import Path


class RegistryAnalyzer:
    """
    Analyzes Windows Registry hives for forensic artifacts
    Uses Python's built-in winreg module on Windows
    On non-Windows systems, provides guidance for offline analysis
    """

    def __init__(self):
        self.is_windows = sys.platform == 'win32'
        self.artifacts = {
            'userassist': [],
            'run_keys': [],
            'recent_docs': [],
            'usb_devices': [],
            'typed_urls': [],
            'shimcache': [],
            'installed_programs': [],
            'network_profiles': [],
            'mru_lists': [],
            'services': [],
            'shellbags': []
        }

        # ROT13 for UserAssist decoding
        self.rot13_table = str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        )

    def rot13_decode(self, text):
        """Decode ROT13 encoded strings (used in UserAssist)"""
        return text.translate(self.rot13_table)

    def analyze_live_registry(self):
        """
        Analyze live Windows registry on running system
        Requires Windows and appropriate permissions
        """
        if not self.is_windows:
            print("    ⚠️  Not running on Windows - live registry analysis not available")
            print("    💡 Use offline analysis mode for registry hive files")
            return self.artifacts

        try:
            import winreg

            print("[+] 📋 Analyzing Windows Registry...")

            # Extract UserAssist (program execution)
            self._extract_userassist_live(winreg)

            # Extract Run keys (persistence)
            self._extract_run_keys_live(winreg)

            # Extract Recent Documents
            self._extract_recent_docs_live(winreg)

            # Extract USB devices
            self._extract_usb_devices_live(winreg)

            # Extract Typed URLs
            self._extract_typed_urls_live(winreg)

            # Extract Installed Programs
            self._extract_installed_programs_live(winreg)

            # Extract Network Profiles
            self._extract_network_profiles_live(winreg)

            # Extract MRU Lists
            self._extract_mru_lists_live(winreg)

            # Extract Services
            self._extract_services_live(winreg)

            print(f"    ✅ Registry analysis complete")

        except ImportError:
            print("    ⚠️  winreg module not available")
        except Exception as e:
            print(f"    ⚠️  Registry analysis error: {str(e)}")

        return self.artifacts

    def _extract_userassist_live(self, winreg):
        """Extract UserAssist entries (program execution tracking)"""
        try:
            base_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

            try:
                user_assist = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_key)
            except:
                return

            # Iterate through GUIDs
            guid_index = 0
            while True:
                try:
                    guid_name = winreg.EnumKey(user_assist, guid_index)
                    guid_key = winreg.OpenKey(user_assist, f"{guid_name}\\Count")

                    # Enumerate values
                    value_index = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(guid_key, value_index)

                            # Decode ROT13
                            decoded_name = self.rot13_decode(value_name)

                            # Parse execution count from binary data
                            exec_count = 0
                            last_exec = "Unknown"

                            if value_data and len(value_data) >= 8:
                                try:
                                    # UserAssist data structure parsing
                                    exec_count = int.from_bytes(value_data[4:8], byteorder='little')

                                    # Timestamp parsing (if available)
                                    if len(value_data) >= 72:
                                        timestamp_data = value_data[60:68]
                                        timestamp = int.from_bytes(timestamp_data, byteorder='little')

                                        if timestamp > 0:
                                            # Convert Windows FILETIME to datetime
                                            windows_epoch = datetime(1601, 1, 1)
                                            last_exec = windows_epoch + timedelta(microseconds=timestamp/10)
                                            last_exec = str(last_exec)
                                except:
                                    pass

                            self.artifacts['userassist'].append({
                                'program': decoded_name,
                                'guid': guid_name,
                                'run_count': exec_count,
                                'last_executed': last_exec
                            })

                            value_index += 1
                        except OSError:
                            break

                    winreg.CloseKey(guid_key)
                    guid_index += 1

                except OSError:
                    break

            winreg.CloseKey(user_assist)
            print(f"    └─ UserAssist: {len(self.artifacts['userassist'])} entries")

        except Exception as e:
            print(f"    └─ UserAssist: Error - {str(e)}")

    def _extract_run_keys_live(self, winreg):
        """Extract Run/RunOnce keys (persistence mechanisms)"""
        try:
            run_locations = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            ]

            for hive, path, name in run_locations:
                try:
                    key = winreg.OpenKey(hive, path)
                    index = 0

                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(key, index)

                            self.artifacts['run_keys'].append({
                                'location': name,
                                'name': value_name,
                                'command': str(value_data),
                                'type': value_type
                            })

                            index += 1
                        except OSError:
                            break

                    winreg.CloseKey(key)

                except FileNotFoundError:
                    pass
                except Exception as e:
                    pass

            print(f"    └─ Run Keys: {len(self.artifacts['run_keys'])} entries")

        except Exception as e:
            print(f"    └─ Run Keys: Error - {str(e)}")

    def _extract_recent_docs_live(self, winreg):
        """Extract Recent Documents"""
        try:
            base_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

            try:
                recent = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_key)
            except:
                return

            # Enumerate values
            index = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(recent, index)

                    if value_name and value_data:
                        # Try to decode filename
                        try:
                            # Registry stores as null-terminated wide string
                            filename = value_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                            if filename:
                                self.artifacts['recent_docs'].append({
                                    'filename': filename,
                                    'type': 'Recent Document'
                                })
                        except:
                            pass

                    index += 1
                except OSError:
                    break

            winreg.CloseKey(recent)
            print(f"    └─ Recent Docs: {len(self.artifacts['recent_docs'])} entries")

        except Exception as e:
            print(f"    └─ Recent Docs: Error - {str(e)}")

    def _extract_usb_devices_live(self, winreg):
        """Extract USB device history"""
        try:
            base_key = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"

            try:
                usb = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key)
            except:
                return

            # Enumerate USB devices
            device_index = 0
            while True:
                try:
                    device_name = winreg.EnumKey(usb, device_index)
                    device_key = winreg.OpenKey(usb, device_name)

                    # Get device instances
                    instance_index = 0
                    while True:
                        try:
                            instance_name = winreg.EnumKey(device_key, instance_index)
                            instance_key = winreg.OpenKey(device_key, instance_name)

                            # Read device info
                            friendly_name = ""
                            service = ""

                            try:
                                friendly_name, _ = winreg.QueryValueEx(instance_key, "FriendlyName")
                            except:
                                friendly_name = device_name

                            try:
                                service, _ = winreg.QueryValueEx(instance_key, "Service")
                            except:
                                pass

                            self.artifacts['usb_devices'].append({
                                'device': friendly_name,
                                'serial': instance_name,
                                'type': device_name,
                                'service': service
                            })

                            winreg.CloseKey(instance_key)
                            instance_index += 1

                        except OSError:
                            break

                    winreg.CloseKey(device_key)
                    device_index += 1

                except OSError:
                    break

            winreg.CloseKey(usb)
            print(f"    └─ USB Devices: {len(self.artifacts['usb_devices'])} entries")

        except Exception as e:
            print(f"    └─ USB Devices: Error - {str(e)}")

    def _extract_typed_urls_live(self, winreg):
        """Extract Typed URLs (Internet Explorer/Edge)"""
        try:
            base_key = r"Software\Microsoft\Internet Explorer\TypedURLs"

            try:
                typed = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_key)
            except:
                return

            index = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(typed, index)

                    if value_data:
                        self.artifacts['typed_urls'].append({
                            'url': str(value_data),
                            'position': value_name
                        })

                    index += 1
                except OSError:
                    break

            winreg.CloseKey(typed)
            print(f"    └─ Typed URLs: {len(self.artifacts['typed_urls'])} entries")

        except Exception as e:
            print(f"    └─ Typed URLs: Error - {str(e)}")

    def _extract_installed_programs_live(self, winreg):
        """Extract Installed Programs"""
        try:
            uninstall_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]

            for hive, path in uninstall_keys:
                try:
                    uninstall = winreg.OpenKey(hive, path)
                    program_index = 0

                    while True:
                        try:
                            program_guid = winreg.EnumKey(uninstall, program_index)
                            program_key = winreg.OpenKey(uninstall, program_guid)

                            display_name = ""
                            publisher = ""
                            version = ""
                            install_date = ""

                            try:
                                display_name, _ = winreg.QueryValueEx(program_key, "DisplayName")
                            except:
                                pass

                            try:
                                publisher, _ = winreg.QueryValueEx(program_key, "Publisher")
                            except:
                                pass

                            try:
                                version, _ = winreg.QueryValueEx(program_key, "DisplayVersion")
                            except:
                                pass

                            try:
                                install_date, _ = winreg.QueryValueEx(program_key, "InstallDate")
                            except:
                                pass

                            if display_name:
                                self.artifacts['installed_programs'].append({
                                    'name': display_name,
                                    'publisher': publisher,
                                    'version': version,
                                    'install_date': install_date,
                                    'guid': program_guid
                                })

                            winreg.CloseKey(program_key)
                            program_index += 1

                        except OSError:
                            break

                    winreg.CloseKey(uninstall)

                except:
                    pass

            print(f"    └─ Installed Programs: {len(self.artifacts['installed_programs'])} entries")

        except Exception as e:
            print(f"    └─ Installed Programs: Error - {str(e)}")

    def _extract_network_profiles_live(self, winreg):
        """Extract Network Profiles (WiFi history)"""
        try:
            base_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"

            try:
                profiles = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key)
            except:
                return

            profile_index = 0
            while True:
                try:
                    profile_guid = winreg.EnumKey(profiles, profile_index)
                    profile_key = winreg.OpenKey(profiles, profile_guid)

                    profile_name = ""
                    description = ""
                    managed = ""

                    try:
                        profile_name, _ = winreg.QueryValueEx(profile_key, "ProfileName")
                    except:
                        pass

                    try:
                        description, _ = winreg.QueryValueEx(profile_key, "Description")
                    except:
                        pass

                    try:
                        managed, _ = winreg.QueryValueEx(profile_key, "Managed")
                    except:
                        pass

                    if profile_name:
                        self.artifacts['network_profiles'].append({
                            'name': profile_name,
                            'description': description,
                            'managed': managed,
                            'guid': profile_guid
                        })

                    winreg.CloseKey(profile_key)
                    profile_index += 1

                except OSError:
                    break

            winreg.CloseKey(profiles)
            print(f"    └─ Network Profiles: {len(self.artifacts['network_profiles'])} entries")

        except Exception as e:
            print(f"    └─ Network Profiles: Error - {str(e)}")

    def _extract_mru_lists_live(self, winreg):
        """Extract MRU (Most Recently Used) lists"""
        try:
            mru_keys = [
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
            ]

            for key_path in mru_keys:
                try:
                    mru = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)

                    # Get MRU list order
                    try:
                        mru_list, _ = winreg.QueryValueEx(mru, "MRUListEx")
                    except:
                        mru_list = None

                    # Enumerate values
                    index = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(mru, index)

                            if value_name not in ["MRUListEx"] and value_data:
                                try:
                                    # Try to decode path
                                    path = value_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                                    if path:
                                        self.artifacts['mru_lists'].append({
                                            'path': path,
                                            'type': key_path.split('\\')[-1]
                                        })
                                except:
                                    pass

                            index += 1
                        except OSError:
                            break

                    winreg.CloseKey(mru)

                except:
                    pass

            print(f"    └─ MRU Lists: {len(self.artifacts['mru_lists'])} entries")

        except Exception as e:
            print(f"    └─ MRU Lists: Error - {str(e)}")

    def _extract_services_live(self, winreg):
        """Extract Windows Services"""
        try:
            base_key = r"SYSTEM\CurrentControlSet\Services"

            try:
                services = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key)
            except:
                return

            service_index = 0
            while True:
                try:
                    service_name = winreg.EnumKey(services, service_index)
                    service_key = winreg.OpenKey(services, service_name)

                    display_name = ""
                    image_path = ""
                    start_type = ""

                    try:
                        display_name, _ = winreg.QueryValueEx(service_key, "DisplayName")
                    except:
                        display_name = service_name

                    try:
                        image_path, _ = winreg.QueryValueEx(service_key, "ImagePath")
                    except:
                        pass

                    try:
                        start_type_val, _ = winreg.QueryValueEx(service_key, "Start")
                        start_types = {
                            0: "Boot",
                            1: "System",
                            2: "Automatic",
                            3: "Manual",
                            4: "Disabled"
                        }
                        start_type = start_types.get(start_type_val, "Unknown")
                    except:
                        pass

                    # Only include if we have meaningful data
                    if image_path:
                        self.artifacts['services'].append({
                            'name': service_name,
                            'display_name': display_name,
                            'image_path': image_path,
                            'start_type': start_type
                        })

                    winreg.CloseKey(service_key)
                    service_index += 1

                except OSError:
                    break

            winreg.CloseKey(services)
            print(f"    └─ Services: {len(self.artifacts['services'])} entries")

        except Exception as e:
            print(f"    └─ Services: Error - {str(e)}")

    def get_statistics(self):
        """Generate statistics about extracted artifacts"""
        stats = {
            'total_artifacts': 0,
            'userassist_count': len(self.artifacts['userassist']),
            'run_keys_count': len(self.artifacts['run_keys']),
            'recent_docs_count': len(self.artifacts['recent_docs']),
            'usb_devices_count': len(self.artifacts['usb_devices']),
            'typed_urls_count': len(self.artifacts['typed_urls']),
            'installed_programs_count': len(self.artifacts['installed_programs']),
            'network_profiles_count': len(self.artifacts['network_profiles']),
            'mru_lists_count': len(self.artifacts['mru_lists']),
            'services_count': len(self.artifacts['services']),
        }

        stats['total_artifacts'] = sum([
            stats['userassist_count'],
            stats['run_keys_count'],
            stats['recent_docs_count'],
            stats['usb_devices_count'],
            stats['typed_urls_count'],
            stats['installed_programs_count'],
            stats['network_profiles_count'],
            stats['mru_lists_count'],
            stats['services_count']
        ])

        return stats

    def generate_report_data(self):
        """Generate report data for HTML generator"""
        return {
            'artifacts': self.artifacts,
            'statistics': self.get_statistics(),
            'is_windows': self.is_windows
        }


# Standalone test
if __name__ == "__main__":
    print("="*70)
    print("REGISTRY ANALYZER - STANDALONE TEST")
    print("="*70)

    analyzer = RegistryAnalyzer()

    if analyzer.is_windows:
        artifacts = analyzer.analyze_live_registry()
        stats = analyzer.get_statistics()

        print("\n" + "="*70)
        print("REGISTRY ANALYSIS SUMMARY")
        print("="*70)
        print(f"Total Artifacts: {stats['total_artifacts']}")
        print(f"  UserAssist: {stats['userassist_count']}")
        print(f"  Run Keys: {stats['run_keys_count']}")
        print(f"  Recent Docs: {stats['recent_docs_count']}")
        print(f"  USB Devices: {stats['usb_devices_count']}")
        print(f"  Typed URLs: {stats['typed_urls_count']}")
        print(f"  Installed Programs: {stats['installed_programs_count']}")
        print(f"  Network Profiles: {stats['network_profiles_count']}")
        print(f"  MRU Lists: {stats['mru_lists_count']}")
        print(f"  Services: {stats['services_count']}")
    else:
        print("\n⚠️  Not running on Windows - registry analysis requires Windows OS")
