"""Knowledge base for agent learning from bug bounty reports and external sources"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import json
import csv
import re
from pathlib import Path
from collections import defaultdict


class VulnerabilityPattern(BaseModel):
    """A vulnerability pattern learned from bug bounty reports"""
    id: str
    vulnerability_type: str
    title: str
    description: str
    reproduction_steps: List[str] = Field(default_factory=list)
    root_cause: Optional[str] = None
    affected_endpoint: Optional[str] = None
    affected_technology: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    source: str  # "bug_bounty", "blog", "research_paper"
    source_id: Optional[str] = None  # BB-1234, URL, etc.
    learned_at: datetime = Field(default_factory=datetime.now)
    times_seen: int = 1
    success_rate: float = 0.0  # If we've tried this technique


class TechniqueLearning(BaseModel):
    """A testing technique learned from various sources"""
    name: str
    description: str
    category: str  # "sql_injection", "xss", "authentication", etc.
    tools: List[str] = Field(default_factory=list)
    payloads: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)  # Signs of success
    prerequisites: List[str] = Field(default_factory=list)
    difficulty: str = "medium"  # "easy", "medium", "hard"
    success_rate: float = 0.0
    learned_from: List[str] = Field(default_factory=list)  # BB-1234, blog URLs


class KnowledgeBase:
    """
    Central knowledge base for all agents

    Features:
    - Ingest bug bounty reports from CSV
    - Extract vulnerability patterns
    - Extract testing techniques
    - Search by vulnerability type, technology, keywords
    - Track what works (success rates)
    - Share learnings between agents
    """

    def __init__(self, storage_dir: str = "knowledge"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # In-memory knowledge stores
        self.vulnerability_patterns: Dict[str, VulnerabilityPattern] = {}
        self.techniques: Dict[str, TechniqueLearning] = {}

        # Indices for fast searching
        self.by_vuln_type: Dict[str, List[str]] = defaultdict(list)
        self.by_technology: Dict[str, List[str]] = defaultdict(list)
        self.by_category: Dict[str, List[str]] = defaultdict(list)

        # Load existing knowledge
        self._load_knowledge()

    def ingest_bug_bounty_csv(self, csv_path: str) -> int:
        """
        Ingest bug bounty reports from CSV file

        Args:
            csv_path: Path to CSV file

        Returns:
            Number of reports ingested
        """
        count = 0

        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    description = row.get('description', '')

                    if not description:
                        continue

                    # Extract vulnerability information
                    pattern = self._extract_vulnerability_pattern(description, count)

                    if pattern:
                        self.add_vulnerability_pattern(pattern)
                        count += 1

        except Exception as e:
            print(f"Error ingesting CSV: {str(e)}")

        return count

    def _extract_vulnerability_pattern(
        self,
        description: str,
        index: int
    ) -> Optional[VulnerabilityPattern]:
        """
        Extract vulnerability pattern from bug bounty report description

        Args:
            description: Report description
            index: Report index

        Returns:
            VulnerabilityPattern if extraction successful
        """
        try:
            # Extract title (first line or sentence)
            lines = description.strip().split('\n')
            title = lines[0][:200] if lines else "Untitled"

            # Extract vulnerability type
            vuln_type = self._detect_vulnerability_type(description)

            # Extract reproduction steps
            repro_steps = self._extract_reproduction_steps(description)

            # Extract affected endpoint
            endpoint = self._extract_endpoint(description)

            # Extract technologies
            technologies = self._extract_technologies(description)

            # Extract techniques
            techniques = self._extract_techniques(description)

            # Detect severity
            severity = self._detect_severity(description)

            pattern = VulnerabilityPattern(
                id=f"BB-{index:04d}",
                vulnerability_type=vuln_type,
                title=title,
                description=description[:500],  # First 500 chars
                reproduction_steps=repro_steps,
                affected_endpoint=endpoint,
                affected_technology=technologies,
                techniques=techniques,
                severity=severity,
                source="bug_bounty",
                source_id=f"BB-{index:04d}"
            )

            return pattern

        except Exception as e:
            print(f"Error extracting pattern: {str(e)}")
            return None

    def _detect_vulnerability_type(self, description: str) -> str:
        """Detect vulnerability type from description"""
        description_lower = description.lower()

        # Common vulnerability patterns
        patterns = {
            "sql_injection": ["sql injection", "sqli", "sql query", "database query"],
            "xss": ["cross-site scripting", "xss", "javascript injection", "reflected xss", "stored xss"],
            "authentication_bypass": ["authentication bypass", "auth bypass", "bypass authentication", "unauthorized access"],
            "idor": ["idor", "insecure direct object reference", "access control", "authorization flaw"],
            "rce": ["remote code execution", "rce", "code execution", "command injection"],
            "csrf": ["csrf", "cross-site request forgery"],
            "ssrf": ["ssrf", "server-side request forgery"],
            "path_traversal": ["path traversal", "directory traversal", "file inclusion"],
            "information_disclosure": ["information disclosure", "sensitive data", "exposed", "leaked"],
            "access_control": ["improper access control", "access control", "permission issue"],
            "crash": ["crash", "denial of service", "dos", "application crash"],
            "domain_validation": ["domain validation", "domain filtering", "domain bypass"],
        }

        for vuln_type, keywords in patterns.items():
            for keyword in keywords:
                if keyword in description_lower:
                    return vuln_type

        return "unknown"

    def _extract_reproduction_steps(self, description: str) -> List[str]:
        """Extract reproduction steps from description"""
        steps = []

        # Look for reproduction steps section
        repro_match = re.search(
            r'(?:reproduction steps?|repro steps?|steps to reproduce|how to reproduce)(.*?)(?:\n\n|$)',
            description,
            re.IGNORECASE | re.DOTALL
        )

        if repro_match:
            repro_text = repro_match.group(1)

            # Extract numbered or bulleted steps
            for match in re.finditer(r'(?:^|\n)\s*[\d\-\*•]\s*(.+)', repro_text):
                step = match.group(1).strip()
                if len(step) > 10:  # Ignore very short steps
                    steps.append(step[:200])  # Limit step length

        return steps[:10]  # Max 10 steps

    def _extract_endpoint(self, description: str) -> Optional[str]:
        """Extract affected endpoint from description"""
        # Look for URLs or API endpoints
        url_match = re.search(r'https?://[^\s<>"]+', description)
        if url_match:
            return url_match.group(0)

        # Look for endpoint patterns like /api/...
        endpoint_match = re.search(r'/[a-zA-Z0-9_/\-\.]+', description)
        if endpoint_match:
            return endpoint_match.group(0)

        return None

    def _extract_technologies(self, description: str) -> List[str]:
        """Extract technologies mentioned in description"""
        technologies = []
        description_lower = description.lower()

        tech_patterns = {
            "android": ["android", "apk", "mobile app"],
            "ios": ["ios", "iphone", "ipad"],
            "web": ["web application", "website", "web app"],
            "api": ["api", "rest api", "graphql"],
            "aws": ["aws", "amazon web services", "s3", "ec2"],
            "javascript": ["javascript", "js", "react", "vue", "angular"],
            "python": ["python", "django", "flask"],
            "java": ["java", "spring"],
            "php": ["php", "wordpress"],
            "sql": ["sql", "mysql", "postgresql", "database"],
        }

        for tech, keywords in tech_patterns.items():
            for keyword in keywords:
                if keyword in description_lower and tech not in technologies:
                    technologies.append(tech)
                    break

        return technologies

    def _extract_techniques(self, description: str) -> List[str]:
        """Extract testing techniques from description"""
        techniques = []
        description_lower = description.lower()

        technique_keywords = {
            "parameter manipulation": ["parameter", "manipulate", "modify parameter"],
            "fuzzing": ["fuzz", "fuzzing", "payload"],
            "brute force": ["brute force", "enumeration"],
            "domain bypass": ["domain bypass", "validation bypass"],
            "intent injection": ["intent", "exported activity"],
            "file upload": ["upload", "file upload"],
            "jwt manipulation": ["jwt", "json web token"],
        }

        for technique, keywords in technique_keywords.items():
            for keyword in keywords:
                if keyword in description_lower and technique not in techniques:
                    techniques.append(technique)
                    break

        return techniques

    def _detect_severity(self, description: str) -> str:
        """Detect severity from description"""
        description_lower = description.lower()

        if any(word in description_lower for word in ["critical", "severe", "rce", "remote code execution"]):
            return "critical"
        elif any(word in description_lower for word in ["high", "authentication bypass", "sensitive data"]):
            return "high"
        elif any(word in description_lower for word in ["medium", "moderate"]):
            return "medium"
        elif any(word in description_lower for word in ["low", "minor", "information disclosure"]):
            return "low"

        return "medium"  # Default

    def add_vulnerability_pattern(self, pattern: VulnerabilityPattern):
        """Add a vulnerability pattern to the knowledge base"""
        self.vulnerability_patterns[pattern.id] = pattern

        # Update indices
        self.by_vuln_type[pattern.vulnerability_type].append(pattern.id)

        for tech in pattern.affected_technology:
            self.by_technology[tech].append(pattern.id)

        # Persist
        self._save_knowledge()

    def add_technique(self, technique: TechniqueLearning):
        """Add a testing technique to the knowledge base"""
        self.techniques[technique.name] = technique
        self.by_category[technique.category].append(technique.name)
        self._save_knowledge()

    def search_by_vulnerability_type(self, vuln_type: str, limit: int = 10) -> List[VulnerabilityPattern]:
        """Search patterns by vulnerability type"""
        pattern_ids = self.by_vuln_type.get(vuln_type, [])[:limit]
        return [self.vulnerability_patterns[pid] for pid in pattern_ids]

    def search_by_technology(self, technology: str, limit: int = 10) -> List[VulnerabilityPattern]:
        """Search patterns by technology"""
        pattern_ids = self.by_technology.get(technology, [])[:limit]
        return [self.vulnerability_patterns[pid] for pid in pattern_ids]

    def search_by_keywords(self, keywords: List[str], limit: int = 10) -> List[VulnerabilityPattern]:
        """Search patterns by keywords"""
        results = []

        for pattern in self.vulnerability_patterns.values():
            score = 0
            text = f"{pattern.title} {pattern.description}".lower()

            for keyword in keywords:
                if keyword.lower() in text:
                    score += 1

            if score > 0:
                results.append((score, pattern))

        # Sort by score and return top matches
        results.sort(reverse=True, key=lambda x: x[0])
        return [p for _, p in results[:limit]]

    def get_techniques_for_category(self, category: str) -> List[TechniqueLearning]:
        """Get testing techniques for a category"""
        technique_names = self.by_category.get(category, [])
        return [self.techniques[name] for name in technique_names]

    def get_relevant_knowledge(
        self,
        context: Dict[str, Any],
        limit: int = 5
    ) -> Dict[str, Any]:
        """
        Get relevant knowledge based on context

        Args:
            context: Dict with keys like 'target', 'technologies', 'vulnerability_types'
            limit: Max results per category

        Returns:
            Dict with relevant patterns and techniques
        """
        results = {
            "vulnerability_patterns": [],
            "techniques": [],
            "similar_cases": []
        }

        # Search by technologies
        if "technologies" in context:
            for tech in context["technologies"]:
                results["vulnerability_patterns"].extend(
                    self.search_by_technology(tech, limit=limit)
                )

        # Search by vulnerability types
        if "vulnerability_types" in context:
            for vuln_type in context["vulnerability_types"]:
                results["vulnerability_patterns"].extend(
                    self.search_by_vulnerability_type(vuln_type, limit=limit)
                )

        # Search by keywords
        if "keywords" in context:
            results["similar_cases"] = self.search_by_keywords(
                context["keywords"],
                limit=limit
            )

        # Deduplicate
        seen_ids = set()
        unique_patterns = []
        for p in results["vulnerability_patterns"]:
            if p.id not in seen_ids:
                unique_patterns.append(p)
                seen_ids.add(p.id)

        results["vulnerability_patterns"] = unique_patterns[:limit]

        return results

    def share_learning(
        self,
        agent_name: str,
        learning: Dict[str, Any]
    ):
        """
        Share a learning from an agent

        Args:
            agent_name: Name of agent sharing knowledge
            learning: Learning data (technique, pattern, insight)
        """
        # Create a file for agent learnings
        learnings_file = self.storage_dir / f"{agent_name}_learnings.jsonl"

        with open(learnings_file, 'a') as f:
            f.write(json.dumps({
                "agent": agent_name,
                "timestamp": datetime.now().isoformat(),
                **learning
            }) + '\n')

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics"""
        return {
            "total_patterns": len(self.vulnerability_patterns),
            "total_techniques": len(self.techniques),
            "vulnerability_types": len(self.by_vuln_type),
            "technologies": len(self.by_technology),
            "categories": len(self.by_category)
        }

    def _save_knowledge(self):
        """Save knowledge to disk"""
        # Save vulnerability patterns
        patterns_file = self.storage_dir / "vulnerability_patterns.json"
        with open(patterns_file, 'w') as f:
            json.dump(
                {pid: p.model_dump() for pid, p in self.vulnerability_patterns.items()},
                f,
                indent=2,
                default=str
            )

        # Save techniques
        techniques_file = self.storage_dir / "techniques.json"
        with open(techniques_file, 'w') as f:
            json.dump(
                {name: t.model_dump() for name, t in self.techniques.items()},
                f,
                indent=2,
                default=str
            )

    def _load_knowledge(self):
        """Load knowledge from disk"""
        # Load vulnerability patterns
        patterns_file = self.storage_dir / "vulnerability_patterns.json"
        if patterns_file.exists():
            try:
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    for pid, pattern_data in data.items():
                        pattern = VulnerabilityPattern(**pattern_data)
                        self.add_vulnerability_pattern(pattern)
            except json.JSONDecodeError as e:
                print(f"⚠️  Warning: Could not load vulnerability patterns (corrupted JSON): {e}")
                print(f"   Knowledge base will start empty. You can re-ingest data if needed.")

        # Load techniques
        techniques_file = self.storage_dir / "techniques.json"
        if techniques_file.exists():
            try:
                with open(techniques_file, 'r') as f:
                    data = json.load(f)
                    for name, technique_data in data.items():
                        technique = TechniqueLearning(**technique_data)
                        self.add_technique(technique)
            except json.JSONDecodeError as e:
                print(f"⚠️  Warning: Could not load techniques (corrupted JSON): {e}")


# Global knowledge base instance
_knowledge_base = None

def get_knowledge_base() -> KnowledgeBase:
    """Get or create global knowledge base"""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
    return _knowledge_base
