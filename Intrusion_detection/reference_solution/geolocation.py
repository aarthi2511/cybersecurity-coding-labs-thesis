# geolocation.py - IP Geolocation Module WITH Caching

import json
import os
from typing import Dict, Optional
from config import INTERNAL_IP_PREFIX, SUSPICIOUS_COUNTRY_LIST, GEOLOCATION_CACHE_FILE


class GeoLocator:
    """
    IP geolocation service with caching.
    
    Uses a simulated database for demonstration.
    Caches lookups to geo_cache.json to avoid repeated lookups.
    """
    
    def __init__(self):
        self.cache = self._load_cache()
   
        self.geo_database = {
            # Attacker IP pool (Beijing/Moscow region)
            "203.0.113.50": {"country": "CN", "city": "Beijing"},
            "203.0.113.51": {"country": "CN", "city": "Beijing"},
            "203.0.113.52": {"country": "CN", "city": "Beijing"},
            "203.0.113.53": {"country": "CN", "city": "Beijing"},
            "203.0.113.60": {"country": "RU", "city": "Moscow"},
            "203.0.113.61": {"country": "RU", "city": "Moscow"},
            "203.0.113.62": {"country": "RU", "city": "Moscow"},
            "203.0.113.63": {"country": "RU", "city": "Moscow"},
            
            # Distributed attack IP pool (US/UK region)
            "198.51.100.10": {"country": "US", "city": "New York"},
            "198.51.100.11": {"country": "US", "city": "San Francisco"},
            "198.51.100.12": {"country": "GB", "city": "London"},
            "198.51.100.13": {"country": "US", "city": "Chicago"},
            "198.51.100.20": {"country": "US", "city": "Los Angeles"},
            "198.51.100.21": {"country": "GB", "city": "Manchester"},
            "198.51.100.22": {"country": "US", "city": "Seattle"},
            "198.51.100.23": {"country": "GB", "city": "Birmingham"},
            
            # Suspicious location IP pool (China)
            "123.125.114.144": {"country": "CN", "city": "Shanghai"},
            "123.125.114.145": {"country": "CN", "city": "Shanghai"},
            "123.125.114.146": {"country": "CN", "city": "Shanghai"},
            "110.242.68.66": {"country": "CN", "city": "Beijing"},
            "110.242.68.67": {"country": "CN", "city": "Beijing"},
            "110.242.68.68": {"country": "CN", "city": "Beijing"},
        }
        
        # Approximate distances between countries (in km)
        self.country_distances = {
            ("US", "CN"): 11000,  # USA to China
            ("US", "RU"): 8000,   # USA to Russia
            ("US", "GB"): 5500,   # USA to UK
            ("US", "KP"): 11000,  # USA to North Korea
            ("US", "IR"): 10000,  # USA to Iran
            ("CN", "RU"): 3000,   # China to Russia
            ("CN", "GB"): 8000,   # China to UK
            ("CN", "KP"): 1000,   # China to North Korea
            ("CN", "IR"): 5000,   # China to Iran
            ("RU", "GB"): 2500,   # Russia to UK
            ("RU", "KP"): 2500,   # Russia to North Korea
            ("RU", "IR"): 2500,   # Russia to Iran
            ("GB", "KP"): 8500,   # UK to North Korea
            ("GB", "IR"): 4500,   # UK to Iran
            ("KP", "IR"): 6000,   # North Korea to Iran
        }
    
    def _load_cache(self) -> Dict:
        """
        Load cached geolocation data from JSON file.
        
        Returns:
            Dictionary of cached IP lookups
        """
        if os.path.exists(GEOLOCATION_CACHE_FILE):
            try:
                with open(GEOLOCATION_CACHE_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_cache(self):
     
        try:
            with open(GEOLOCATION_CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save geo cache: {e}")
    
    def lookup(self, ip: str) -> Optional[Dict]:
        """
        Get geolocation information for an IP address.
        Uses cache first, then database, then saves to cache.
        """
        # Check if internal IP
        if ip.startswith(INTERNAL_IP_PREFIX):
            return {
                "country": "US",
                "city": "Internal Network",
                "internal": True
            }

        if ip in self.cache:
            return self.cache[ip]
     
        if ip in self.geo_database:
            geo_info = self.geo_database[ip]
          
            self.cache[ip] = geo_info
            self._save_cache()
            return geo_info
   
        unknown_info = {
            "country": "Unknown",
            "city": "Unknown"
        }
        self.cache[ip] = unknown_info
        self._save_cache()
        return unknown_info
    
    def is_suspicious_country(self, country_code: str) -> bool:
       
        return country_code in SUSPICIOUS_COUNTRY_LIST
    
    def get_location_string(self, ip: str) -> str:
       
        info = self.lookup(ip)
        if not info:
            return "Unknown"
        
        if info.get("internal"):
            return "Internal Network"
        
        city = info.get("city", "Unknown")
        country = info.get("country", "Unknown")
        return f"{city}, {country}"
    
    def get_distance(self, country1: str, country2: str) -> Optional[int]:
        
        if country1 == country2:
            return 0
        
        key1 = (country1, country2)
        key2 = (country2, country1)
        
        if key1 in self.country_distances:
            return self.country_distances[key1]
        elif key2 in self.country_distances:
            return self.country_distances[key2]
        else:
          
            return 5000
        
        if info.get("internal"):
            return "Internal Network"
        
        city = info.get("city", "Unknown")
        country = info.get("country", "Unknown")
        
        return f"{city}, {country}"



_geolocator = None


def get_geolocator() -> GeoLocator:
    """Get global GeoLocator instance."""
    global _geolocator
    if _geolocator is None:
        _geolocator = GeoLocator()
    return _geolocator