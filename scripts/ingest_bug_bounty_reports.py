#!/usr/bin/env python3
"""Ingest bug bounty reports into knowledge base"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.learning import get_knowledge_base

def main():
    """Ingest bug bounty reports from CSV"""
    print("=" * 70)
    print("BUG BOUNTY REPORT INGESTION")
    print("=" * 70)

    kb = get_knowledge_base()

    # Path to bug bounty CSV
    csv_path = Path.home() / "Downloads" / "Sai-RT.csv"

    if not csv_path.exists():
        print(f"\n❌ CSV file not found: {csv_path}")
        print("\nPlease ensure Sai-RT.csv is in your Downloads folder.")
        sys.exit(1)

    print(f"\n📁 Loading bug bounty reports from: {csv_path}")

    # Ingest reports
    count = kb.ingest_bug_bounty_csv(str(csv_path))

    print(f"\n✅ Successfully ingested {count} bug bounty reports!")

    # Display statistics
    stats = kb.get_stats()
    print("\n📊 Knowledge Base Statistics:")
    print(f"  • Total Vulnerability Patterns: {stats['total_patterns']}")
    print(f"  • Vulnerability Types: {stats['vulnerability_types']}")
    print(f"  • Technologies Covered: {stats['technologies']}")

    # Show some examples
    print("\n🔍 Sample Vulnerability Patterns:")

    # SQL Injection patterns
    sql_patterns = kb.search_by_vulnerability_type("sql_injection", limit=3)
    if sql_patterns:
        print("\n  SQL Injection Patterns:")
        for p in sql_patterns:
            print(f"    • {p.id}: {p.title[:80]}...")

    # XSS patterns
    xss_patterns = kb.search_by_vulnerability_type("xss", limit=3)
    if xss_patterns:
        print("\n  XSS Patterns:")
        for p in xss_patterns:
            print(f"    • {p.id}: {p.title[:80]}...")

    # Authentication bypass patterns
    auth_patterns = kb.search_by_vulnerability_type("authentication_bypass", limit=3)
    if auth_patterns:
        print("\n  Authentication Bypass Patterns:")
        for p in auth_patterns:
            print(f"    • {p.id}: {p.title[:80]}...")

    # Android patterns
    android_patterns = kb.search_by_technology("android", limit=3)
    if android_patterns:
        print("\n  Android-specific Patterns:")
        for p in android_patterns:
            print(f"    • {p.id}: {p.title[:80]}...")

    print("\n" + "=" * 70)
    print("✅ KNOWLEDGE BASE READY")
    print("=" * 70)

    print("\nAgents can now:")
    print("  • Search for vulnerability patterns")
    print("  • Learn testing techniques from real exploits")
    print("  • Share knowledge with each other")
    print("  • Apply learnings to new targets")

    print("\n💡 Next: Run test_agent_collaboration.py to see agents in action!")

if __name__ == "__main__":
    main()
