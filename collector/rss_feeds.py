"""
RSS Feed Monitor - monitors security researcher feeds for emerging threats
"""

import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict
import re


# Security-focused RSS feeds
SECURITY_FEEDS = [
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "type": "government"
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "type": "researcher"
    },
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "type": "news"
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "type": "news"
    },
]


def fetch_feed(feed_info: Dict) -> List[Dict]:
    """Fetch and parse a single RSS feed"""
    results = []
    
    try:
        response = requests.get(feed_info["url"], timeout=15, headers={
            "User-Agent": "HRTIP/1.0 Security Research Tool"
        })
        response.raise_for_status()
        
        root = ET.fromstring(response.content)
        
        # Handle both RSS and Atom formats
        items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
        
        for item in items[:10]:  # Limit to 10 per feed
            # RSS format
            title = item.find("title")
            link = item.find("link")
            description = item.find("description")
            pub_date = item.find("pubDate")
            
            # Atom format fallback
            if title is None:
                title = item.find("{http://www.w3.org/2005/Atom}title")
            if link is None:
                link_elem = item.find("{http://www.w3.org/2005/Atom}link")
                link_url = link_elem.get("href") if link_elem is not None else None
            else:
                link_url = link.text
            if description is None:
                description = item.find("{http://www.w3.org/2005/Atom}summary")
            
            results.append({
                "source": feed_info["name"],
                "source_type": feed_info["type"],
                "title": title.text if title is not None else "No title",
                "url": link_url,
                "description": description.text[:500] if description is not None and description.text else "",
                "published": pub_date.text if pub_date is not None else None,
                "collected_at": datetime.now(timezone.utc).isoformat()
            })
        
        print(f"[RSS] {feed_info['name']}: {len(results)} articles")
        return results
        
    except Exception as e:
        print(f"[RSS] {feed_info['name']}: Error - {e}")
        return []


def collect() -> List[Dict]:
    """Collect from all RSS feeds"""
    all_articles = []
    
    for feed in SECURITY_FEEDS:
        articles = fetch_feed(feed)
        all_articles.extend(articles)
    
    return all_articles


def filter_relevant(articles: List[Dict], keywords: List[str] = None) -> List[Dict]:
    """Filter articles by relevance to healthcare/retail threats"""
    if keywords is None:
        keywords = [
            "healthcare", "hospital", "medical", "patient", "hipaa",
            "retail", "pos", "payment", "credit card", "pharmacy",
            "ransomware", "breach", "vulnerability", "cve", "malware",
            "apt", "threat actor", "campaign"
        ]
    
    relevant = []
    for article in articles:
        text = f"{article['title']} {article['description']}".lower()
        if any(kw in text for kw in keywords):
            article["matched_keywords"] = [kw for kw in keywords if kw in text]
            relevant.append(article)
    
    return relevant


if __name__ == "__main__":
    print("=" * 60)
    print("HRTIP RSS Feed Monitor")
    print("=" * 60)
    
    articles = collect()
    print(f"\nTotal articles collected: {len(articles)}")
    
    print("\n" + "=" * 60)
    print("Filtering for healthcare/retail relevance...")
    print("=" * 60)
    
    relevant = filter_relevant(articles)
    print(f"Relevant articles: {len(relevant)}")
    
    for article in relevant[:5]:
        print(f"\n[{article['source']}] {article['title']}")
        print(f"  Keywords: {article.get('matched_keywords', [])}")
        print(f"  URL: {article['url']}")
