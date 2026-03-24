"""Multi-judge verification prompts, check orders, and ORM function checks.

Used by taint_analyzer for the multi-step verification pipeline adapted
from Pecker 3.0.
"""

# ---------------------------------------------------------------------------
# Multi-judge verification prompts (adapted from Pecker)
# ---------------------------------------------------------------------------

MULTI_JUDGE_CHECKS = {
    "sqli": {
        # Java SQLI check order (6 checks — matches Pecker exactly):
        # sink_check -> xml_taint_num_check -> sink_taint_fixed_check ->
        # sink_taint_exist_check -> sanitizer_check -> taint_check
        "sink_check": (
            "Analyze the code and determine: Are the SQL queries constructed using "
            "ONLY parameterized queries (PreparedStatement with ? placeholders, "
            "MyBatis #{param}, JPA :param, or ORM Criteria API)? "
            "If ALL SQL is parameterized → return True (safe, no vuln). "
            "If ANY SQL uses string concatenation (+), String.format(), "
            "MyBatis ${param}, or dynamic table/column names built from variables → "
            "return False (unsafe, vuln exists). "
            "IMPORTANT: MyBatis #{...} is parameterized (safe), ${...} is string "
            "interpolation (unsafe). Do NOT confuse the two."
        ),
        "xml_taint_num_check": (
            "For MyBatis XML mapper sinks with ${...} interpolation: "
            "Check if ALL taint variables inside ${...} patterns are numeric types "
            "(byte, short, int, Integer, long, Long, float, double, boolean, "
            "or List<numeric>). Numeric types CANNOT carry SQL injection payloads. "
            "Return True if ALL ${...} variables are numeric types (safe). "
            "Return False if ANY ${...} variable is a String, Object, Map, or "
            "other non-numeric type. "
            "If no MyBatis ${...} patterns exist, skip this check (return False)."
        ),
        "sink_taint_fixed_check": (
            "Check if the parameters flowing into the SQL sink are hardcoded "
            "constants, compile-time constants (static final), or fixed values "
            "that cannot be influenced by user input. "
            "Return True if ALL taint parameters are hardcoded/constant (safe). "
            "Return False if any parameter comes from a variable or method return."
        ),
        "sink_taint_exist_check": (
            "For MyBatis XML sinks: verify that ${...} taint variables actually "
            "exist in the SQL statement. Sometimes the XML file has been sanitized "
            "or the ${...} has been replaced with #{...} in a newer version. "
            "Return True if there are NO ${...} patterns in the SQL (safe). "
            "Return False if ${...} patterns are present (taint exists)."
        ),
        "sanitizer_check": (
            "Analyze the code for SQL injection sanitization. Check if ALL "
            "user-controlled variables that reach SQL queries are validated via: "
            "whitelist validation, enum constraints, strict regex, type casting "
            "to numeric types, or authorization/permission checks that limit "
            "the controllable input space. "
            "Return True if effective sanitization exists for ALL risky variables. "
            "Return False if any variable reaches the sink without sanitization."
        ),
        "taint_check": (
            "Trace the flow of user input through the code. Does any non-numeric "
            "user-controlled parameter flow into a SQL sink (directly or through "
            "intermediate method calls, field access, method chaining, or Map gets)? "
            "Consider type sensitivity: Map values are key-sensitive, Objects are "
            "field-sensitive, Lists are index-sensitive. "
            "Return True if taint does NOT reach the sink (safe). "
            "Return False if taint reaches the sink (vulnerable)."
        ),
    },
    "rce": {
        # RCE check order (same across Java/Go/Python):
        # sink_check -> input_check -> sanitizer_check -> taint_check
        "sink_check": (
            "Determine if the code calls command execution functions: "
            "Runtime.getRuntime().exec(), ProcessBuilder, ProcessBuilder.start(), "
            "ScriptEngine.eval(), or third-party command execution utilities "
            "(e.g., RuntimeUtil.exec(), commons-exec). "
            "If such functions are called, return False (dangerous sink exists). "
            "Otherwise return True (no dangerous sink)."
        ),
        "input_check": (
            "Determine if the route/endpoint method receives external user input. "
            "If no user input is received, return True (safe). "
            "If ALL inputs are numeric types, return True (safe). "
            "Otherwise return False."
        ),
        "sanitizer_check": (
            "Check if there are authorization functions, validation logic, or "
            "whitelist/blacklist checks that would prevent malicious command "
            "injection. If strict validation exists, return True. "
            "If only simple null checks or no validation, return False."
        ),
        "taint_check": (
            "Trace user input flow: does any user-controlled parameter reach "
            "the command execution sink? Consider direct and indirect flows "
            "(through method calls, string concatenation, etc.). "
            "Return True if taint does NOT reach the sink, False if it does."
        ),
    },
    "xxe": {
        # XXE check order (Java/Python):
        # sink_check -> input_check -> feature_check -> taint_check
        "sink_check": (
            "Check if the code uses known XXE-vulnerable XML parsing libraries: "
            "DocumentBuilderFactory, SAXParserFactory, DOM4J, XMLInputFactory, "
            "TransformerFactory, Validator, SchemaFactory, SAXReader, SAXBuilder, "
            "Unmarshaller, XPathExpression, XMLDecoder. "
            "If such a library is used, return False (dangerous sink). "
            "Otherwise return True."
        ),
        "input_check": (
            "Determine if the XML content being parsed comes from user input "
            "(HTTP request body, uploaded file, user-provided URL). "
            "If the XML is from a trusted internal source only, return True (safe). "
            "If user can control the XML content, return False."
        ),
        "feature_check": (
            "Check if the XML parser has explicit security features configured: "
            "- disallow-doctype-decl = true "
            "- external-general-entities = false "
            "- external-parameter-entities = false "
            "- XMLConstants.ACCESS_EXTERNAL_DTD = '' "
            "- XMLConstants.ACCESS_EXTERNAL_SCHEMA = '' "
            "If security features are properly configured, return True (safe). "
            "Otherwise return False."
        ),
        "taint_check": (
            "Trace whether user-controlled XML data reaches the XML parsing sink. "
            "Return True if user input does NOT reach the parser, False if it does."
        ),
    },
    "ssrf": {
        # SSRF check order:
        # sink_check -> input_check -> sanitizer_check -> taint_check
        "sink_check": (
            "Check if the code makes HTTP/network requests using: "
            "URL.openConnection(), HttpURLConnection, HttpClient, RestTemplate, "
            "WebClient, OkHttp, or similar. "
            "If such functions are used, return False. Otherwise return True."
        ),
        "input_check": (
            "Determine if the URL/host/port used in the network request comes "
            "from user input. If the URL is entirely hardcoded or from trusted "
            "config, return True (safe). If user can influence the URL, return False."
        ),
        "sanitizer_check": (
            "Check if there is URL validation: domain whitelist, IP blacklist "
            "(blocking 127.0.0.1, 169.254.x.x, 10.x.x.x, etc.), protocol "
            "restriction (only http/https). If robust validation exists, "
            "return True. Otherwise return False."
        ),
        "taint_check": (
            "Trace user input flow to the network request sink. Does user input "
            "reach the URL construction? Return True if not, False if yes."
        ),
    },
    "path_traversal": {
        # Path traversal check order:
        # sink_check -> input_check -> canonicalization_check -> sanitizer_check -> taint_check
        "sink_check": (
            "Check if the code performs file system operations using: "
            "new File(), FileInputStream, FileOutputStream, FileReader, FileWriter, "
            "RandomAccessFile, Paths.get(), Path.of(), Files.read*/write*/copy/move/delete, "
            "ServletContext.getRealPath(), ClassPathResource, FileSystemResource, "
            "ResourceLoader.getResource(), or static file serving handlers. "
            "Also check for Zip/archive extraction operations (ZipInputStream, ZipFile). "
            "If such functions are called, return False (dangerous sink exists). "
            "Otherwise return True (no file system sink)."
        ),
        "input_check": (
            "Determine if the file path used in the file system operation comes "
            "from user input. Check for: HTTP request parameters, URL path components "
            "(request.getPathInfo(), getServletPath(), getRequestURI(), request.pathInfo(), "
            "request.params(), request.splat()), uploaded file names (getSubmittedFileName()), "
            "HTTP headers, or any other user-controlled string. "
            "If the file path is entirely hardcoded or from trusted config, return True (safe). "
            "If user can influence ANY part of the file path, return False."
        ),
        "canonicalization_check": (
            "Check if the code properly canonicalizes the path AND validates the result: "
            "1. Path canonicalization: getCanonicalPath(), toRealPath(), normalize() "
            "2. Followed by a bounds check: canonicalPath.startsWith(baseDir) or equivalent. "
            "BOTH steps are required — canonicalization alone is NOT sufficient. "
            "Also check for: "
            "- Null byte rejection (\\x00) "
            "- URL-encoded traversal detection (%2e%2e, %2f, %252e%252e — double encoding) "
            "- chroot / sandbox / jail directory enforcement "
            "Return True if proper canonicalization + bounds checking exists (safe). "
            "Return False if missing or incomplete (e.g., only checks for '..' literal "
            "but not URL-encoded variants, or canonicalizes but doesn't verify bounds)."
        ),
        "sanitizer_check": (
            "Check if there is path sanitization that effectively prevents traversal: "
            "- Whitelist validation: comparing against a fixed set of allowed filenames/paths "
            "- Strict regex that rejects any path containing '..' in any encoding "
            "- Path component validation (no '/' or '\\' in user-supplied filename) "
            "- Framework-level path security (e.g., Spring Security resource handler "
            "  with proper configuration) "
            "A blacklist that only checks for '..' literal but not %2e%2e/%252e%252e "
            "is INEFFECTIVE — return False. "
            "Return True if effective sanitization exists, False otherwise."
        ),
        "taint_check": (
            "Trace user input flow: does any user-controlled input reach the file "
            "path construction? Consider direct concatenation (baseDir + userInput), "
            "Path.resolve(userInput), String.format with user input, and indirect "
            "flows through method calls. "
            "Also consider framework-level path resolution where the framework "
            "resolves requested URLs to file system paths (e.g., static file serving). "
            "Return True if taint does NOT reach the file path sink, False if it does."
        ),
    },
}

# ---------------------------------------------------------------------------
# Check orders per language/vuln type (matches Pecker exactly)
# ---------------------------------------------------------------------------

MULTI_JUDGE_CHECK_ORDERS = {
    "java": {
        "sqli": ["sink_check", "xml_taint_num_check", "sink_taint_fixed_check",
                 "sink_taint_exist_check", "sanitizer_check", "taint_check"],
        "rce": ["sink_check", "input_check", "sanitizer_check", "taint_check"],
        "xxe": ["sink_check", "input_check", "feature_check", "taint_check"],
        "ssrf": ["sink_check", "input_check", "sanitizer_check", "taint_check"],
        "path_traversal": ["sink_check", "input_check", "canonicalization_check",
                           "sanitizer_check", "taint_check"],
    },
    "go": {
        "sqli": ["function_check", "sink_check", "input_check", "sanitizer_check", "taint_check"],
        "rce": ["sink_check", "input_check", "sanitizer_check", "taint_check"],
        "path_traversal": ["sink_check", "input_check", "canonicalization_check",
                           "sanitizer_check", "taint_check"],
    },
    "python": {
        "sqli": ["function_check", "sink_check", "input_check", "sanitizer_check", "taint_check"],
        "rce": ["sink_check", "input_check", "sanitizer_check", "taint_check"],
        "xxe": ["sink_check", "input_check", "feature_check", "taint_check"],
        "path_traversal": ["sink_check", "input_check", "canonicalization_check",
                           "sanitizer_check", "taint_check"],
    },
}

# ---------------------------------------------------------------------------
# Additional checks for Go/Python (function_check — ORM framework detection)
# ---------------------------------------------------------------------------

FUNCTION_CHECK = {
    "go": (
        "Check if the SQL operations use a safe ORM framework (GORM, sqlx with "
        "named parameters, Ent, XORM with builder methods). If the code uses "
        "ORM methods that automatically parameterize queries (e.g., db.Where(), "
        "db.Find(), sqlx.NamedExec with :param), return True (safe). "
        "If it uses raw SQL via db.Raw(), db.Exec() with string concatenation, "
        "or fmt.Sprintf() for SQL building, return False (unsafe)."
    ),
    "python": (
        "Check if the SQL operations use a safe ORM framework (SQLAlchemy ORM, "
        "Django ORM, Peewee, Tortoise ORM). If the code uses ORM methods that "
        "automatically parameterize queries (e.g., Model.objects.filter(), "
        "session.query().filter(), %s placeholders with params tuple), return "
        "True (safe). If it uses raw SQL via connection.execute() with f-strings, "
        ".format(), or % string formatting, return False (unsafe)."
    ),
}
