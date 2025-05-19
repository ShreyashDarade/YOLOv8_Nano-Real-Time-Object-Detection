MITRE Mapper Agent System 

Overview 

This space documents the core "agentic" workflow powering the MITRE ATT&CK mapping microservice. It includes: 

Data normalization and analysis 

Multi-tool MITRE technique mapping 

Enrichment with context and recommendations 

Output structure and confidence modeling 

This system is architected as a multi-stage pipeline of agents. Each agent is responsible for a key part of the MITRE technique mapping and enrichment workflow. 

 

Agent Architecture Overview 

The system uses three primary agents: 

AlertAnalysisAgent: Normalizes incoming alert/event/log data into a uniform set of features. 

MITREMappingAgent: Applies multiple mapping tools (rules, regex, BM25, vector search, LLM, etc.) and consolidates results. 

MITREEnrichmentAgent: Enriches mapped MITRE techniques with names, tactics, descriptions, and actionable recommendations. 

Each agent is designed to be stateless for scalability and composability, receiving and returning Python dictionaries/lists in a well-documented schema. 

 

1. AlertAnalysisAgent 

Overview 

AlertAnalysisAgent is the first agent in the MITRE mapping pipeline. Its core mission is to normalize, clean, and feature-engineer all incoming alerts/logs/events, converting them into a rich, uniform set of fields ("indicators") that downstream mapping tools and agents can reliably use—regardless of the original source format or log schema. 

This normalization step is critical in cybersecurity pipelines because alert/log data is often inconsistent, nested, or highly variable across products and environments. 

 

Responsibilities 

Input normalization: Accept raw data from SIEM, EDR, NDR, log aggregator, or custom applications. 

Field extraction: Parse out key features: alert type, severity, hostnames, messages, timestamps, process details, Sigma/CVE IDs, anomaly sentences, and all available metadata. 

Text preprocessing: Clean and concatenate fields for both keyword/regex and vector embedding based tools. 

Resilience: Handle missing or malformed fields gracefully, supplying robust defaults. 

Schema transformation: Convert multiple possible input schemas (flat, nested, Elasticsearch, custom) into a consistent output dictionary. 

 

Input / Output Contract 

Input 

Any alert/event/log record, typically a dictionary. 

Can be a flat dict, nested (e.g., ES _source), or with varying field names. 

Example input: 

{ 
  "alert_id": "abcd-1234", 
  "msg": "Suspicious PowerShell command detected", 
  "type": 19900, 
  "severity": 3, 
  "metadata": { 
    "anomalySentences": ["powershell.exe -enc ..."], 
    "sigmaAlerts": [ 
      {"id": "SigmaProcExec", "tags": ["attack.t1059"], "description": "Process execution anomaly"} 
    ] 
  }, 
  "command_lines": ["powershell.exe -enc ..."], 
  "involved_processes": [], 
  "cve_id": "CVE-2021-1234" 
} 
  

Output 

A normalized, canonical Python dict (indicators) with all features mapping tools expect. 

Output example: 

{ 
  "alert_id": "abcd-1234", 
  "alert_type_id": 19900, 
  "host": "", 
  "msg": "Suspicious PowerShell command detected", 
  "severity": 3, 
  "type": 19900, 
  "type_mapping": { 
      "name": "AlertXtendProvena", 
      "display_name": "AI-Provenance", 
      "related_tids": ["T1059"] 
  }, 
  "metadata": { 
      "anomalySentences": ["powershell.exe -enc ..."], 
      "sigmaAlerts": [...], 
      "unauthorizedDnsServers": [], 
      "unauthorizedDomains": [] 
  }, 
 
  "cve_id": "CVE-2021-1234", 
  "mitre_technique_ids": ["T1059"],   # extracted from sigma tags 
  "combined_text_for_keywords": "...", # for keyword/regex tools 
  "combined_text_for_vectors": "...",  # for embedding tools 
  ... 
} 
  

 

Detailed Step-By-Step Logic 

1. Extract Core Fields 

alert_id: 

Always included for traceability. 

alert_type_id: 

Usually the integer “type” field, e.g. 19900. 

msg: 

Alert message, human-readable. 

severity: 

Usually 0–3 (Low, Medium, High). 

host: 

Hostname, if present. 

type: 

Synonymous with alert_type_id for downstream tools. 

metadata: 

All nested metadata, including anomalies, sigma alerts, unauthorized DNS/domains, etc. 

2. Mapping Info Extraction 

Type mapping: 

Uses ALERT_TYPE_INFO from config to convert numeric type to human-readable name and display. 

Example: 

enum_name, display = ALERT_TYPE_INFO.get( 
    t_id, 
    (f"UnknownType{t_id}", str(t_id)) 
) 
type_mapping = { 
    "name": enum_name, 
    "display_name": display, 
    "related_tids": related_tids 
} 
  

Rule-based related technique IDs: 

Looks up ALERT_TYPE_TO_TECHNIQUE for this type, collects all related MITRE IDs. 

Sigma and CVE extraction: 

Calls extract_specific_ids(alert_data) (see utils.py) to find: 

Sigma rule ID 

CVE ID 

Any technique IDs embedded in Sigma tags 

These are added to sigma_rule_id, cve_id, and mitre_technique_ids fields. 

3. Metadata Normalization 

Anomaly Sentences: 

Extracts from metadata.anomalySentences (list of interesting log messages, anomalies, etc.). 

Sigma Alerts: 

Either a dict (Sigma rule ID → alert list) or a flat list. Converted to a consistent list-of-dicts for downstream use. 

Unauthorized DNS/Domains: 

Populates lists for network-based anomaly mapping. 

4. Process Extraction (Feature Engineering) 

Involved Processes: 

If not present, attempts to extract them from raw_event_details using a regex-based helper (extract_processes_from_sentences). 

Text Features for Mapping: 

combined_text_for_keywords: 

Concatenates all raw details, command lines, involved processes for robust regex/keyword search. 

combined_text_for_vectors: 

Combines alert message and raw event details for vector embedding tools. 

indicators["combined_text_for_keywords"] = clean_text(" ".join(kw_parts)) 
indicators["combined_text_for_vectors"] = clean_text(" ".join(vec_parts)) 
  

5. Graceful Handling of Edge Cases 

Missing fields: 

Supplies safe defaults (empty strings, lists) if any field is absent. 

Field harmonization: 

Handles multiple field names for the same concept (e.g., type vs alert_type_id). 

Handles both flat and deeply nested JSON structures. 

 

AlertAnalysisAgent is the universal translator: 

Allows all downstream mapping and enrichment agents to work with any alert/log format, any SIEM or EDR product, and any custom event type. 

Abstracts away differences in log schemas, ensuring that new tools or rule sets can be added without constantly updating field-extraction code everywhere. 

Drives higher accuracy and lower false positives/negatives in MITRE mapping. 

 

 

 

Absolutely! Here’s a deep-dive for each mapping tool used by MITREMappingAgent, in the style of an internal wiki or Atlassian Confluence page. 

 

2.MITREMappingAgent 

1. ContextualMappingTool (contextual_mapping_tool.py) 

Purpose: 

 Performs advanced hybrid mapping by blending BM25 text search, vector similarity, and LLM-generated summary of alert context for most relevant MITRE techniques. 

How It Works: 

Loads all MITRE techniques from JSON (name, description, tactics). 

Vector Search: Uses pre-built vector DB for semantic similarity  

LLM Summary: Summarizes context using OpenAI, then encodes with embedding model. 

Rank:  vector scores using an alpha parameter (default 0.6). 

Returns: Top K techniques with confidence labels. 

Key Code (simplified): 

def execute(self, alert: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]: 
    ctx    = self._build_context(alert) 
    tokens = ctx.split() 
 
    # 1. LLM-generated summary for richer embedding 
    summary = self._generate_summary(ctx, [t["name"] for t in self.techs[:self.top_k]]) 
 
    emb = embedding_model.encode(summary, convert_to_tensor=False).tolist() 
 
    # 2. Blend BM25 and vector similarity 
    hits = self._hybrid_rank(emb, tokens) 
    return [ 
        { 
            "tid": h["tid"], 
            "confidence": 1.0 if h["confidence"] == "High" else 0.5 if h["confidence"] == "Medium" else 0.25, 
            "source": self.NAME 
        } 
        for h in hits 
    ] 
  

Input: 

alert: Normalized alert/indicator dictionary. 

Output: 

List of dicts: {"tid": Txxxx, "confidence": float, "source": "ContextualMappingTool"} 

When Used: 

To combine the strengths of search, embeddings, and context-rich summarization. 

Especially strong when logs are verbose or have strong context. 

 

2. CveLookupTool (cve_tool.py) 

Purpose: 

 Maps CVE IDs in alerts to MITRE techniques by querying NVD APIs for any ATT&CK technique references in CVE entries. 

How It Works: 

Calls NVD’s v2.0 (and v1.0 as fallback) API with the given CVE ID. 

Extracts technique IDs from any MITRE references in the response. 

Returns matches with moderate confidence. 

Key Code: 

def execute(self, cve_id=None, **kwargs): 
    mappings = [] 
    # ... HTTP request code (see full listing above) 
    for tid in tech_ids: 
        mappings.append({ 
            "technique_id": tid, 
            "confidence":   0.7, 
            "source":       f"{self.NAME}:{cve_id}" 
        }) 
    return mappings 
  

Input: 

cve_id (from alert data, or None). 

Output: 

List of dicts: {"technique_id": "Txxxx", "confidence": 0.7, "source": "CveLookupTool:CVE-..."} 

When Used: 

If alert contains a CVE; maps known vulnerabilities to ATT&CK patterns. 

 

3. HybridBm25PatternTool (hybrid_bm25_tool.py) 

Purpose: 

 Performs pure BM25 search (classic IR) and regex matching on alert context against all technique descriptions and pre-built patterns. 

How It Works: 

Loads MITRE techniques and pre-compiled regex patterns from config. 

Builds BM25 index over descriptions. 

Combines regex/NER matches (very high confidence) with top BM25 matches. 

Deduplicates on technique ID and returns the top results. 

Key Code: 

def execute(self, alert: Dict[str, Any], **kwargs) -> List[Dict[str, Any]]: 
    context = self._build_context(alert) 
    doc = self.nlp(context) 
    ner_entities = [ent.text for ent in doc.ents if ent.text.strip()] 
 
    # 1. Regex matches 
    regex_hits = ... # matches on context and entities 
    # 2. BM25 matches 
    bm25_hits = ... # scores on context tokens 
    # 3. Merge, dedupe, return top_k 
    ... 
    return final 
  

Input: 

alert: Alert/indicator dict. 

Output: 

List of dicts: {"tid": "Txxxx", "confidence": float, "source": "Regex:..." or "BM25"} 

When Used: 

When there is sufficient log context, or common techniques are easily keyword/regex matched. 

 

4. KeywordRegexTool (keyword_tool.py) 

Purpose: 

 Scans the alert’s text for pre-configured regex or keyword patterns mapped to MITRE techniques. 

How It Works: 

Uses compiled patterns from config.py (COMPILED_TECHNIQUE_KEYWORDS). 

Runs regex search over search_text. 

Returns all matched techniques, with associated confidence and source. 

Key Code: 

def execute(self, search_text=None, **kwargs): 
    mappings = [] 
    for tid, patterns in COMPILED_TECHNIQUE_KEYWORDS.items(): 
        for pattern_info in patterns: 
            if pattern_info['regex'].search(search_text): 
                mappings.append({...}) 
    return mappings 
  

Input: 

search_text: Cleaned string concatenating log/process fields. 

Output: 

List of dicts: {"technique_id": "Txxxx", "confidence": float, "source": "KeywordRegexTool:..."} 

When Used: 

When specific patterns or signatures are present in logs (even short ones). 

Great for signature-driven detections. 

 

5. PyAttckTool (pyattck_tool.py) 

Purpose: 

 Enrichment only. 

 Given a technique ID, returns structured MITRE details (name, description, tactics) from the local pyattck/JSON cache. 

How It Works: 

Looks up technique_id in local MITRE data cache (loaded at startup). 

Returns all available metadata for that technique. 

Key Code: 

def execute(self, technique_id=None, **kwargs): 
    if not technique_id: return None 
    details = get_technique_details(technique_id) 
    return details 
  

Input: 

technique_id 

Output: 

Dict: { "name": "...", "tactics": [...], "description": "..." } 

When Used: 

Not for mapping, but for enriching mapped results in MITREEnrichmentAgent. 

 

6. RuleBasedTool (rule_tool.py) 

Purpose: 

 Provides hard-coded 1:1 or 1:many mappings for known alert types (e.g., AlertType=19900 always → T1059). 

How It Works: 

Looks up alert type in ALERT_TYPE_TO_TECHNIQUE (from config). 

Returns pre-defined technique(s) with confidence and human source hint. 

Key Code: 

def execute(self, alert_type_id=None, **kwargs): 
    if alert_type_id and alert_type_id in ALERT_TYPE_TO_TECHNIQUE: 
        for mapping_info in ALERT_TYPE_TO_TECHNIQUE[alert_type_id]: 
            mappings.append({...}) 
    return mappings 
  

Input: 

alert_type_id: Integer alert type code. 

Output: 

List of dicts: {"technique_id": "Txxxx", "confidence": float, "source": "RuleBasedTool:..."} 

When Used: 

For high-confidence, zero-ambiguity mappings (e.g., system alerts mapped to unique techniques). 

 

7. SigmaRuleLookupTool (sigma_tool.py) 

Purpose: 

 (Placeholder/optional) 

 Looks up external Sigma rule IDs to find directly tagged MITRE techniques. 

How It Works: 

Intended to query a Sigma rule registry/database for MITRE tags. 

Currently a stub: always returns empty or placeholder data unless implemented. 

Key Code: 

def execute(self, sigma_rule_id=None, **kwargs): 
    # TODO: Implement real lookup; currently placeholder 
    mitre_tids = [] # Should be filled by DB/API result 
    for tid in mitre_tids: 
        mappings.append({...}) 
    return mappings 
  

Input: 

sigma_rule_id: The ID from Sigma rules in the alert. 

Output: 

List of dicts: {"technique_id": "Txxxx", "confidence": float, "source": "SigmaRuleLookupTool:..."} 

When Used: 

If you maintain a Sigma rules database with MITRE tagging. 

Highest trust when available. 

 

8. VectorSearchTool (vector_tool.py) 

Purpose: 

 Runs vector similarity search over MITRE technique embeddings using a vector database (ChromaDB). 

How It Works: 

Encodes search_text using SentenceTransformers (default: all-MiniLM-L6-v2). 

Queries ChromaDB for the most similar MITRE technique embeddings. 

Scales similarity to a confidence value. 

Returns top K hits above the configured threshold. 

Key Code: 

def execute(self, search_text=None, **kwargs): 
    raw_emb = embedding_model.encode(search_text, convert_to_tensor=False) 
    query_emb = raw_emb.tolist() 
    candidates = find_similar_techniques_in_db(query_emb, top_k=VECTOR_SEARCH_TOP_K) 
    for c in candidates: 
        ... 
        mappings.append({ 
            "technique_id": c["technique_id"], 
            "confidence": confidence, 
            "source": f"{self.NAME}_sim:{sim:.2f}" 
        }) 
    return mappings 
  

Input: 

search_text: Cleaned string (usually alert message + raw event details). 

Output: 

List of dicts: {"technique_id": "Txxxx", "confidence": float, "source": "VectorSearchTool_sim:..."} 

When Used: 

When you need semantic, “fuzzy” matching, especially for novel log lines or unknown techniques. 

How These Fit Together 

In MITREMappingAgent, these tools are prioritized and all executed in parallel for each alert. Their top (and sometimes second) matches are merged using confidence, priority, and source-tracking logic, so you always get the highest-quality, lowest-false-positive MITRE mappings for any incoming alert. 

 

Certainly! Here is a deep, pointwise, and code-linked Atlassian Confluence-style documentation for the MITREEnrichmentAgent, covering what it does, how it works, its workflow, and how it fits in the overall pipeline. 

 

3.MITREEnrichmentAgent 

Overview 

The MITREEnrichmentAgent is the final step in the MITRE mapping pipeline. Its job is to enrich raw MITRE technique mappings with detailed contextual information (name, description, tactics, etc.) and, most importantly, generate highly technical recommendations for detection, mitigation, and response—using a mix of local data and AI-powered (OpenAI) suggestions. 

This agent transforms a set of raw mappings (just technique IDs + confidence + sources) into actionable, readable, and informative objects suitable for human analysts, automated SOAR playbooks, dashboards, or tickets. 

 

Responsibilities 

Look up MITRE ATT&CK technique metadata (name, tactics, description) for each mapped technique ID. 

Generate technical recommendations for each mapping (ideally 3 per technique), using OpenAI if available, or fallback heuristics if not. 

Cache recommendations to avoid repeated LLM/API calls for the same technique. 

Return a unified enriched object per technique, with all information a security engineer or automation system needs. 

 

Input/Output 

Input 

A dictionary (mappings) as produced by MITREMappingAgent, e.g.: 

{ 
  "T1059": { 
    "confidence": 1.0, 
    "sources": ["HybridBm25PatternTool", "SigmaTag"], 
    "priority": 8 
  }, 
  "T1562.001": { 
    "confidence": 0.8, 
    "sources": ["KeywordRegexTool"], 
    "priority": 7 
  } 
  # ...etc 
} 
  

Output 

A list of enriched mappings, each a dict, for example: 

[ 
  { 
    "technique_id": "T1059", 
    "confidence": 1.0, 
    "sources": ["HybridBm25PatternTool", "SigmaTag"], 
    "name": "Command and Scripting Interpreter", 
    "description": "Adversaries may abuse command and script interpreters...", 
    "tactics": ["Execution"], 
    "recommendations": [ 
      "Configure Sysmon Event ID 1 (Process Creation)...", 
      "Enable PowerShell ScriptBlock logging...", 
      "Implement application whitelisting for powershell.exe and cmd.exe..." 
    ], 
    # Any additional MITRE fields, as desired 
  }, 
  # ... 
] 
  

 

Detailed Workflow (Step-by-Step) 

1. Initialization 

Loads the PyAttckTool for local MITRE data enrichment. 

Loads the OpenAI API key from the environment, if set. 

Initializes a recommendation cache (self.recommendation_cache) for performance. 

Prepares a set of default fallback recommendations in case OpenAI is not available or fails. 

def __init__(self): 
    self.pyattck = PyAttckTool() 
    self.openai_api_key = os.getenv("OPENAI_API_KEY") 
    self.recommendation_cache = {} 
    self.default_recommendations = [ ... ]  # See code 
  

 

2. Enriching Each Mapping (The enrich() Method) 

Iterates over all input technique IDs and their mapping metadata. 

Calls PyAttckTool to get MITRE technique details: 

name, description, tactics, and any other fields. 

Generates technical recommendations via LLM (or fallback). 

Assembles a fully enriched dict with all fields for that technique. 

def enrich(self, mappings: dict) -> list: 
    enriched = [] 
    for tid, info in mappings.items(): 
        details = self.pyattck.execute(technique_id=tid) or {} 
        # Extract technique details 
        technique_name = details.get("name", "Unknown Technique") 
        technique_description = details.get("description", "No description available") 
        tactics = details.get("tactics", []) 
        # Generate recommendations 
        recommendations = self.generate_openai_recommendations( 
            tid, technique_name, technique_description, tactics 
        ) 
        enriched.append({ 
            "technique_id": tid, 
            "confidence": info["confidence"], 
            "sources": info["sources"], 
            "recommendations": recommendations, 
            **details 
        }) 
    return enriched 
  

 

3. Recommendation Generation (generate_openai_recommendations) 

- If OpenAI API key is present: 

Checks the cache first (avoid API cost and latency). 

Builds a prompt: Supplies the technique ID, name, tactics, and description. 

Calls OpenAI ChatCompletion API (e.g., GPT-4o), asking for 3 very specific, technical recommendations. 

Extracts bullet points or lines from the LLM response. 

- If OpenAI is unavailable or fails: 

Falls back to default, static recommendations or simple heuristics. 

def generate_openai_recommendations(self, technique_id, technique_name, technique_description, tactics): 
    if not self.openai_api_key: 
        return self.default_recommendations 
    # Check cache first 
    if technique_id in self.recommendation_cache: 
        return self.recommendation_cache[technique_id] 
    # Build prompt, call API, extract bullet points, cache result 
    # ...see code above for full details... 
  

Prompt engineering ensures the output is precise, technical, and immediately actionable (e.g., specific event IDs, configuration parameters, SIEM rules—not generic "apply least privilege"). 

 

4. Returns Enriched List 

Each mapping now includes: 

technique_id (e.g., T1059) 

confidence (float) 

sources (tools that contributed to this mapping) 

name, description, tactics (from MITRE ATT&CK) 

recommendations (list of actionable steps) 

(Optionally) any other MITRE metadata 

 

Why MITREEnrichmentAgent is Critical 

Bridges the gap between raw automation and actionable intelligence. 

Human analysts need the name, description, and “what next?” for each mapping—not just IDs and scores. 

Automated systems (SOAR, ticketing, reporting) can use these recommendations to enrich incidents, trigger playbooks, or document findings. 

Ensures every mapping is operationally useful: immediately ready for triage, detection engineering, or remediation. 

 

Pipeline Example 

Before Enrichment 

{ 
  "T1059": { 
    "confidence": 1.0, 
    "sources": ["HybridBm25PatternTool"], 
    "priority": 8 
  } 
} 
  

After Enrichment 

[ 
  { 
    "technique_id": "T1059", 
    "confidence": 1.0, 
    "sources": ["HybridBm25PatternTool"], 
    "name": "Command and Scripting Interpreter", 
    "description": "Adversaries may abuse command and script interpreters...", 
    "tactics": ["Execution"], 
    "recommendations": [ 
      "Configure Sysmon Event ID 1 (Process Creation)...", 
      "Enable PowerShell ScriptBlock logging...", 
      "Implement application whitelisting for powershell.exe and cmd.exe..." 
    ] 
  } 
] 
  

Troubleshooting & Best Practices 

If recommendations are generic or blank, check the OpenAI API key and model version. 

To speed up performance and reduce cost, recommendations are cached per technique. 

You can add custom, organization-specific default recommendations to self.default_recommendations. 

Output can be safely extended to include more MITRE metadata (platforms, detection, data sources, etc.) by modifying the details dict in enrich(). 

 

 

 

 

 

 

 

 

Certainly! Here’s an extremely detailed breakdown of config.py in your MITRE mapping pipeline, including the purpose of each section, how values are used, and practical examples for every block. This will help new engineers, documentation readers, and integrators understand exactly how to customize and extend the configuration. 

 

config.py — Configuration Reference 

 

1. Alert Type to MITRE Technique Mapping 

ALERT_TYPE_TO_TECHNIQUE 

Purpose: 

 Provides a hard-coded mapping from your product’s or SIEM’s alert type codes (integers) to MITRE ATT&CK technique IDs, confidence levels, and human-readable hints. 

Usage: 

Used by the RuleBasedTool for fast, zero-API mapping. 

Example: An alert type ID 19100 ("CPU Usage High") is mapped to MITRE technique T1496. 

Structure: 

ALERT_TYPE_TO_TECHNIQUE = { 
    <alert_type_id>: [ 
        { 
            "technique_id": "<TXXXX or TXXXX.YYY>", 
            "confidence": <float 0–1>, 
            "source_hint": "<human-readable>" 
        }, 
        ... 
    ], 
    ... 
} 
  

Example: 

19100: [{"technique_id": "T1496", "confidence": 0.8, "source_hint": "Device CPU Usage High"}], 
19500: [{"technique_id": "T1550.003", "confidence": 0.8, "source_hint": "Unauthorized SSID Connection"}], 
  

Practical Note: 

 If you add a new alert type to your product/SIEM, add an entry here for instant mapping. 

 

2. Alert Type Metadata 

ALERT_TYPE_INFO 

Purpose: 

 Maps alert type IDs to enum-like names and display strings for better readability in UI and outputs. 

Usage: 

Used in the API output for consistent and human-friendly alert type info. 

Structure: 

ALERT_TYPE_INFO = { 
    <alert_type_id>: ("<EnumName>", "<Display Name>"), 
    ... 
} 
  

Example: 

19500: ("AlertXtendUnauthorizedSsid", "Unauthorized SSID Connection"), 
19900: ("AlertXtendProvena", "AI-Provenance"), 
  

 

3. Aliases 

ALIASES 

Purpose: 

 Normalizes certain common tokens or tool-specific terms into canonical keywords for easier searching and mapping. 

Usage: 

Used during text preprocessing before keyword/regex and vector search. 

Structure: 

ALIASES = { 
    "<alias>": "<canonical_form>", 
    ... 
} 
  

Example: 

"sh": "shell",  
"cmd": "windows_shell", 
"powershell": "windows_shell", 
"docker-credential-wincred": "docker_credential_helper" 
  

 

4. Keyword/Regex Patterns 

TECHNIQUE_KEYWORDS & COMPILED_TECHNIQUE_KEYWORDS 

Purpose: 

 Maps MITRE technique IDs to lists of regex patterns/keywords for keyword-based detection. 

Usage: 

Used by the KeywordRegexTool and HybridBm25PatternTool to map text (logs, commands, messages) to MITRE techniques. 

Structure: 

TECHNIQUE_KEYWORDS = { 
    "<technique_id>": [ 
        { 
            "pattern": "<regex_pattern>", 
            "confidence": <float>, 
            "source_hint": "<explanation>" 
        }, 
        ... 
    ], 
    ... 
} 
  

COMPILED_TECHNIQUE_KEYWORDS is the same, but the regex is precompiled for speed. 

Example: 

'T1055.011': [ 
    {'pattern': r'\bExtra\s+Window\s+Memory\b', 'confidence': 0.85, 'source_hint': 'Defense Evasion via OS API'}, 
    {'pattern': r'\bEWM\s+injection\b', 'confidence': 0.8, 'source_hint': 'Privilege Escalation via OS API'}, 
], 
'T1053.005': [ 
    {'pattern': r'\bScheduled\s+Task\b', 'confidence': 0.75, 'source_hint': 'Windows Scheduled Task'}, 
    {'pattern': r'\bschtasks(?:.exe)?\s+(?:/create|/query|/delete|/change)\b', 'confidence': 0.9, 'source_hint': 'Scheduled Task Command'}, 
], 
  

How to Add: 

 To add a new keyword for mapping a log to a MITRE technique, add a pattern under the correct technique ID. 

 

5. Hybrid BM25 Tool Settings 

Purpose: 

 Configures hybrid search tools for combining BM25 (lexical) and embedding (vector) similarity. 

Key Fields: 

HYBRID_BM25_ATTACK_FILE: Path to MITRE JSON file (e.g., ./enterprise-attack.json) 

HYBRID_BM25_TOP_K: How many top results to keep (default: 3) 

Example: 

HYBRID_BM25_ATTACK_FILE = "./enterprise-attack.json" 
HYBRID_BM25_TOP_K = 3 
  

 

6. Tool Priorities 

TOOL_PRIORITIES 

Purpose: 

 Assigns priorities to each mapping tool for merging and deconfliction (higher is more trusted). 

Usage: 

Used by MITREMappingAgent when consolidating overlapping tool results. 

Example: 

TOOL_PRIORITIES = { 
    "SigmaTag": 20, 
    "SigmaRuleLookupTool": 10, 
    "CveLookupTool": 9, 
    "HybridBm25PatternTool": 8, 
    ... 
    "LlmFallbackTool": 3 
} 
  

 

7. Confidence & Reporting Thresholds 

Purpose: 

 Sets system-wide constants for the minimum score needed for reporting and baseline confidence. 

Fields: 

DEFAULT_CONFIDENCE: Baseline for low-confidence mappings (default: 0.1) 

MIN_REPORTING_CONFIDENCE: Minimum for mapping to be reported in output (default: 0.4) 

 

8. External Lookup Endpoints 

Purpose: 

 Stores endpoints for any external lookups (Sigma, NVD, etc). 

Fields: 

SIGMA_LOOKUP_ENDPOINT: URL for Sigma rule lookups. 

NVD_API_KEY: API key for NVD (National Vulnerability Database). 

CVE_LOOKUP_ENDPOINT: URL for CVE lookups. 

Example: 

SIGMA_LOOKUP_ENDPOINT = "http://internal-sigma-lookup/lookup" 
NVD_API_KEY = "your-nvd-key" 
CVE_LOOKUP_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0" 
  

 

9. Vector Search Configuration 

Purpose: 

 Configures the embedding model, vector DB path, Chroma collection, etc. 

Key Fields: 

VECTOR_SEARCH_ENABLED: True/False toggle for vector search. 

EMBEDDING_MODEL_NAME: Name of Hugging Face sentence-transformers model to use (e.g., "all-MiniLM-L6-v2") 

VECTOR_DB_PATH: Filesystem path for ChromaDB data. 

VECTOR_DB_COLLECTION: Name of the ChromaDB collection for MITRE techniques. 

VECTOR_SEARCH_TOP_K: How many top results to retrieve. 

VECTOR_SIMILARITY_THRESHOLD: Minimum similarity for mapping to count (0.0–1.0). 

Example: 

VECTOR_SEARCH_ENABLED = True 
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2" 
VECTOR_DB_PATH = "./vector_db_storage" 
VECTOR_DB_COLLECTION = "mitre_techniques" 
VECTOR_SEARCH_TOP_K = 3 
VECTOR_SIMILARITY_THRESHOLD = 0.35 
  

 

10. OpenAI LLM Settings 

Purpose: 

 Holds model name, fallback, and temperature for any OpenAI-powered tools. 

Fields: 

OPENAI_MODEL: Default OpenAI chat model name. 

OPENAI_FALLBACK_MODEL: Fallback OpenAI model. 

OPENAI_TEMPERATURE: Sampling temperature for OpenAI calls. 

Example: 

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini-2024-07-18") 
OPENAI_FALLBACK_MODEL = os.getenv("OPENAI_FALLBACK_MODEL", "gpt-4.1-mini-2025-04-14") 
OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.9")) 
  

 

How to Extend config.py 

New Alert Type: 

 Add a new entry to both ALERT_TYPE_TO_TECHNIQUE and ALERT_TYPE_INFO. 

New Keyword Mapping: 

 Add a new regex pattern under TECHNIQUE_KEYWORDS for the right MITRE technique ID. 

Change Model or Embedding: 

 Update EMBEDDING_MODEL_NAME to use any supported sentence-transformer. 

Adjust Thresholds: 

 Increase MIN_REPORTING_CONFIDENCE for stricter output, or decrease for more inclusive results. 

Plug in Your Own APIs: 

 Change SIGMA_LOOKUP_ENDPOINT or CVE_LOOKUP_ENDPOINT to point at your organization’s threat intel backend. 

 

Sample Usage in Code 

# Example: Use config to select mappings 
from config import ALERT_TYPE_TO_TECHNIQUE, TECHNIQUE_KEYWORDS 
 
# Look up hard-coded mapping for a new alert 
alert_type_id = 19500 
techniques = ALERT_TYPE_TO_TECHNIQUE.get(alert_type_id, []) 
# Output: [{'technique_id': 'T1550.003', 'confidence': 0.8, ...}] 
 
# Use regex keywords to find matches in an alert message 
patterns = TECHNIQUE_KEYWORDS.get("T1053.005", []) 
# Output: [ ...pattern dicts... ] 
  

 

Absolutely! Here’s a deep-dive, professional documentation-style explanation of your vector_store subpackage for the MITRE mapping system, suitable for Atlassian Confluence (or similar wiki), including technical design, data flow, and code references. 

 

Vector Store Subsystem 

 

Overview 

The vector_store package provides the embedding-based semantic search infrastructure that powers advanced MITRE technique mapping. It enables tools to perform fast, scalable, and intelligent similarity search between an alert’s context and the corpus of MITRE ATT&CK techniques using a vector database (ChromaDB). 

Main Use: Semantic (embedding) search and retrieval. 

Database: ChromaDB (embedded, disk-persistent, or optionally in-memory). 

Embedding Model: Sentence Transformers (e.g., all-MiniLM-L6-v2). 

 

Submodule Structure 

vector_store/ 
  ├── client.py      # Handles ChromaDB client/collection lifecycle 
  ├── indexer.py     # Indexes MITRE techniques as vectors in ChromaDB 
  └── search.py      # Provides nearest neighbor search API for mappings 
  

 

1. client.py — ChromaDB Client Management 

Role: 

 Initializes, caches, and provides access to the ChromaDB client and MITRE technique collection. 

Key Functions 

get_chroma_client() 

Returns a persistent ChromaDB client (singleton). 

Initializes with path from config (VECTOR_DB_PATH). 

Handles ImportError gracefully if ChromaDB is missing. 

get_mitre_collection() 

Returns the MITRE techniques collection (VECTOR_DB_COLLECTION). 

Calls get_chroma_client(), gets or creates the named collection. 

Prepares for upserting or querying vectors. 

Example Usage 

from vector_store.client import get_mitre_collection 
collection = get_mitre_collection() 
# Now you can .upsert() or .query() on the collection. 
  

 

2. indexer.py — MITRE Technique Vector Indexing 

Role: 

 Populates the ChromaDB collection with embeddings and metadata for all MITRE ATT&CK techniques from the local JSON file. 

Workflow 

Load MITRE JSON: 

 Reads enterprise-attack.json (path from config or local directory). 

Extract Techniques: 

 Parses every technique with an ID and description. 

Compute Embeddings: 

 Uses the configured sentence transformer to generate an embedding for each technique (using name + description). 

Build Metadata: 

 Collects name, tactics, platforms, data sources, URL, etc. for each technique. 

Batch Upsert: 

 Inserts embeddings, metadata, and original text into the ChromaDB collection in batches for efficiency. 

Final Count: 

 Optionally logs/returns the number of vectors now in the collection. 

Example Code Block 

# Index all techniques (used during system initialization) 
from vector_store.indexer import run_indexer 
run_indexer() 
  

Example Data Flow 

Field 

Purpose 

ids 

Technique IDs (e.g., "T1059.001") 

embeddings 

384-dim vector from embedding model 

metadatas 

Dicts: name, tactics, platforms, URL 

documents 

The text used to generate the embedding 

 

3. search.py — Vector Similarity Search 

Role: 

 Provides a high-level function to find the most similar MITRE techniques to a given alert (embedding). 

Key Function 

find_similar_techniques_in_db(query_embedding, top_k=3) 

Performs a nearest neighbor search in ChromaDB. 

Computes cosine distance, converts to [0,1] similarity. 

Filters results below a minimum similarity threshold (VECTOR_SIMILARITY_THRESHOLD from config). 

Returns the top K most similar techniques, with all metadata. 

Example Output 

[ 
  { 
    'technique_id': 'T1059', 
    'similarity': 0.91, 
    'source': 'VectorSearchTool (Doc: Adversaries may abuse ...)', 
    'metadata': { ... } 
  }, 
  ... 
] 
  

How It Works 

Embedding Query: 

 Accepts a pre-computed vector for the alert or context. 

Database Search: 

 ChromaDB returns nearest neighbors (vector IDs + distances). 

Postprocessing: 

Converts cosine distance to similarity (sim = 1.0 - (distance/2.0)). 

Filters and sorts by similarity. 

Returns technique ID, similarity, and rich metadata. 

Example Usage 

from vector_store.search import find_similar_techniques_in_db 
results = find_similar_techniques_in_db(alert_embedding, top_k=3) 
for result in results: 
    print(result["technique_id"], result["similarity"]) 
  

 

Data Model: What Gets Stored in ChromaDB? 

Each record/document contains: 

ID: MITRE technique ID (e.g., "T1059.001") 

Embedding: Model-generated vector 

Metadata: Name, tactics, platforms, data sources, URL 

Document: Full text (name + description, etc.) 

 

Integration Points 

VectorSearchTool uses find_similar_techniques_in_db for mapping. 

ContextualMappingTool and HybridBm25PatternTool can leverage embeddings as part of hybrid ranking. 

The indexer runs automatically if the database is empty on startup. 

 

Example: End-to-End Data Flow 

Indexer: 

Loads MITRE JSON 

Embeds every technique 

Populates ChromaDB 

At Query Time: 

Alert is embedded (using the same sentence transformer). 

find_similar_techniques_in_db returns most similar techniques. 

System uses similarity score to set mapping confidence. 

 

Advanced Notes 

Performance: ChromaDB is lightweight, in-process, and highly efficient for small/medium threat intelligence datasets. 

Batching: Indexer batches upserts for speed; searching is optimized for top-K retrieval. 

Extensibility: You can add more fields to metadata (e.g., detection rules, mitigation links) and query/filter them in Chroma. 

Model Selection: You can switch to larger or domain-specific embedding models by changing EMBEDDING_MODEL_NAME in config. 

 

Troubleshooting 

If ChromaDB is not installed or the vector DB is missing, tools will gracefully fall back or disable vector search (see logging). 

Embedding model mismatch (during indexing vs. query) may degrade mapping accuracy — always keep them in sync! 

 

Typical Setup & Reindex 

If you change your MITRE corpus or embedding model: 

Delete or clear the VECTOR_DB_PATH directory. 

Re-run the indexer.py (run_indexer()). 

Restart your service. 

 

 

 

 

Absolutely! Below you’ll find deep, Confluence-ready documentation for each of the following core modules: app.py, mitre_data.py, and utils.py. 

 This is structured for clarity, onboarding, and cross-functional review. 

 

MITRE Mapping Service — Module Documentation 

 

app.py — REST API Service Entrypoint 

 

Purpose 

Main Flask application file: exposes the /map_alert and /health endpoints. 

Wires together the analysis, mapping, and enrichment agents. 

Handles alert normalization, input format variance, error reporting, and output structuring. 

 

Major Components & Flow 

1. Service Initialization 

Loads environment variables and sets up logging. 

Imports all agents: AlertAnalysisAgent, MITREMappingAgent, MITREEnrichmentAgent. 

Initializes MITRE data and, if enabled, vector store (ChromaDB). 

2. Agent Instantiation 

analysis_agent = AlertAnalysisAgent() 
mapping_agent = MITREMappingAgent() 
enrichment_agent = MITREEnrichmentAgent() 
  

All requests will flow through these agents, in order. 

 

3. /map_alert [POST] Endpoint 

Input: 

Accepts JSON in various formats: direct, nested, or Elasticsearch document. 

Key Steps: 

Format Handling: 

Detects format (e.g., ES _source, nested, or flat) and normalizes. 

Extracts main alert data and unique alert_id. 

Normalization: 

Calls normalize_alert_data(alert_data) to harmonize the input. 

Agent Pipeline: 

AlertAnalysisAgent.analyze() → MITREMappingAgent.generate_mappings() → MITREEnrichmentAgent.enrich(). 

Filtering and Output: 

Applies confidence threshold. 

Sorts mappings by confidence. 

Returns detailed mapping objects (technique_id, name, description, tactics, sources, recommendations). 

Adds a summary block (total mappings, high confidence, tactics covered, UTC timestamp). 

Example Output: 

{ 
  "alert_id": "abcd-1234", 
  "mappings": [ 
    { 
      "technique_id": "T1059", 
      "name": "...", 
      "description": "...", 
      "tactics": ["Execution"], 
      "confidence": 1.0, 
      "sources": ["HybridBm25PatternTool", "SigmaTag"], 
      "recommendations": ["Configure Sysmon ...", ...], 
      "recommendation_details": {...} 
    } 
  ], 
  "summary": {...}, 
  "processed_at": "2025-05-19T12:34:56Z" 
} 
  

Error Handling: 

Returns clear error messages and codes for non-JSON, malformed, or empty input. 

Full stack trace on critical failure (logs only). 

 

4. /health [GET] Endpoint 

Returns JSON { status: OK/Error, details: {mitre_data: Loaded/Unavailable, ...} } 

Useful for monitoring and orchestration. 

 

5. Helper Functions 

extract_from_properties(properties): Handles ES “properties” mapping extraction. 

normalize_alert_data(alert_data): Standardizes alert into a canonical dict for the pipeline. 

 

Best Practices 

Always POST valid JSON alerts to /map_alert. 

For bulk processing, POST alerts one by one (the system is stateless). 

Use /health for monitoring service availability. 

 

mitre_data.py — MITRE Technique Data Cache and Loader 

 

Purpose 

Centralizes loading, parsing, and caching of MITRE ATT&CK corpus from local JSON. 

Provides programmatic access to technique metadata (ID, name, tactics, description). 

Triggers vector store (re)indexing if necessary. 

 

Major Functions 

1. initialize_mitre_data() 

Loads the enterprise-attack.json file from disk (path is relative to code location). 

Builds an in-memory cache (_technique_cache) mapping technique IDs to dicts: 

{ "name": ..., "tactics": [...], "description": ... } 

If vector search is enabled and ChromaDB is empty, runs the vector indexer. 

Idempotent: Called at service start and on every health check. 

2. get_attack() 

Returns the loaded MITRE technique cache (calls initialize_mitre_data()). 

3. get_technique_details(technique_id) 

Returns the {name, tactics, description} dict for a given MITRE technique ID. 

Returns None and logs a warning if not found. 

 

Practical Workflow 

On Service Boot: 

initialize_mitre_data() loads techniques into memory for fast access. 

Ensures vector DB is ready (triggers indexing if empty). 

At Query Time: 

Any agent/tool needing technique metadata calls get_technique_details(). 

 

Advanced Usage 

Add new fields to the MITRE JSON and extend the parser for more enrichment (e.g., detection, mitigation, platforms). 

Plug in alternate or updated MITRE datasets for custom deployments. 

 

Troubleshooting 

If MITRE data is missing/corrupt, the system logs an error and returns a cache miss. 

 

utils.py — Utility Functions 

 

Purpose 

Houses common helper functions for cleaning, feature extraction, and parsing in alert processing. 

 

Key Functions 

1. clean_text(text) 

Basic normalization (lowercasing, type checking). 

TODO: Extend with more NLP normalization (stopwords, punctuation, stemming). 

2. extract_processes_from_sentences(sentences) 

Tries to extract executable/process/script names from text (alert message, anomaly, raw details). 

Uses regex for file extensions and simple heuristics. 

Returns a list of process names. 

3. extract_specific_ids(alert_data) 

Finds Sigma rule IDs, CVE IDs, and MITRE technique IDs embedded in alert metadata. 

Handles both flat and nested alert formats. 

Scans tags in metadata.sigmaAlerts for MITRE technique tags (e.g., attack.t1070.002). 

Cleans and normalizes IDs (always uppercased, always CVE-YYYY-NNNN format if possible). 

Returns a tuple: (sigma_id, cve_id) and adds mitre_technique_ids to alert_data in-place. 

 

Usage Example 

from utils import clean_text, extract_processes_from_sentences, extract_specific_ids 
 
txt = "powershell.exe -enc ..." 
cleaned = clean_text(txt)  # 'powershell.exe -enc ...' 
 
procs = extract_processes_from_sentences(["User executes cmd.exe ..."]) 
# ['cmd.exe'] 
 
sigma_id, cve_id = extract_specific_ids(alert_dict) 
# Also updates alert_dict['mitre_technique_ids'] 
  

 

 
