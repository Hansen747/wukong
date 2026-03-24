"""Sink knowledge references and structured sink definitions.

Used by taint_analyzer and related agents. Contains:
- Free-text sink descriptions (SQLI_SINKS, RCE_SINKS, XXE_SINKS, etc.)
- Structured sink definitions in ClassName#method format (STRUCTURED_SINKS)
- Grep patterns for pre-scanning (SINK_GREP_PATTERNS)
"""

# ---------------------------------------------------------------------------
# Free-text sink descriptions (embedded in system prompts)
# ---------------------------------------------------------------------------

SQLI_SINKS = """
## SQL Injection Sinks (Java)
- java.sql.Statement: executeQuery, executeUpdate, addBatch, executeLargeUpdate
- java.sql.Connection: prepareStatement, prepareCall, nativeSQL
- javax.persistence.EntityManager: createQuery, createNativeQuery
- JdbcTemplate: batchUpdate, execute, update, queryForList, queryForObject, query*
- Hibernate Session/SharedSessionContract: createQuery, createSQLQuery, createNativeQuery
- MyBatis XML mapper: ${...} patterns (dollar-sign interpolation, NOT #{...})
- InfluxDB: query
- PageHelper: orderBy, setOrderBy
- Ebean: createSqlQuery, createSqlUpdate
- ClickHouse DataSource constructor
- Any raw SQL string concatenation with + operator
- String.format() used to build SQL
"""

RCE_SINKS = """
## Remote Code Execution Sinks (Java)
- java.lang.Runtime: exec()
- java.lang.ProcessBuilder: constructor, start()
- javax.script.ScriptEngine: eval()
- Spring SpEL: Expression.getValue(), ExpressionParser.parseExpression()
- Server-side template injection (Velocity, FreeMarker, Thymeleaf with user input)
- Reflection: Class.forName() + Method.invoke() with user-controlled class/method names
"""

XXE_SINKS = """
## XML External Entity (XXE) Sinks (Java)
- org.dom4j.DocumentHelper: parseText
- org.dom4j.io.SAXReader: read
- DocumentBuilder: parse
- XMLInputFactory: createXMLStreamReader
- SAXParser: parse
- SAXBuilder/SAXEngine: build
- javax.xml.transform.Transformer: transform
- XPathExpression: evaluate
- javax.xml.bind.Unmarshaller: unmarshal
- XMLReader: parse
- Digester: parse, asyncParse
- javax.xml.validation.Validator: validate
- javax.xml.validation.SchemaFactory: newSchema
- org.apache.poi.xssf.extractor.XSSFExportToXml: exportToXML
- Any XML parser WITHOUT explicit disabling of external entities
  (http://apache.org/xml/features/disallow-doctype-decl = true)
"""

SSRF_SINKS = """
## Server-Side Request Forgery (SSRF) Sinks (Java)
- java.net.URL: openConnection, openStream
- java.net.HttpURLConnection: connect
- org.apache.http.client.HttpClient: execute
- RestTemplate: getForObject, postForObject, exchange
- WebClient: get, post, put, delete
- OkHttp: newCall
- Any HTTP client where the URL is constructed from user input
"""

PATH_TRAVERSAL_SINKS = """
## Path Traversal / Directory Traversal Sinks (CWE-22, CWE-23, CWE-36)

### File I/O constructors & operations
- java.io.File: <init>, exists, delete, listFiles, list, mkdir, mkdirs, renameTo
- java.io.FileInputStream: <init>
- java.io.FileOutputStream: <init>
- java.io.FileReader: <init>
- java.io.FileWriter: <init>
- java.io.RandomAccessFile: <init>

### NIO Path & Files operations
- java.nio.file.Paths: get
- java.nio.file.Path: of, resolve, resolveSibling
- java.nio.file.Files: readAllBytes, readAllLines, readString, write, copy, move, \
delete, deleteIfExists, exists, newInputStream, newOutputStream, \
newBufferedReader, newBufferedWriter, lines, walk, list, createFile, \
createDirectory, createDirectories

### Servlet / Spring resource access
- javax.servlet.ServletContext: getRealPath, getResource, getResourceAsStream
- jakarta.servlet.ServletContext: getRealPath, getResource, getResourceAsStream
- org.springframework.core.io.ClassPathResource: <init>
- org.springframework.core.io.FileSystemResource: <init>
- org.springframework.core.io.UrlResource: <init>
- org.springframework.core.io.ResourceLoader: getResource
- org.springframework.util.ResourceUtils: getFile, getURL

### Static file serving (framework-level)
- spark.Spark: staticFiles, staticFileLocation, externalStaticFileLocation
- spark.staticfiles.StaticFilesConfiguration: consume, getContent
- org.springframework.web.servlet.resource.ResourceHttpRequestHandler: handleRequest

### Archive / Zip operations (Zip Slip — CWE-22 variant)
- java.util.zip.ZipInputStream: getNextEntry
- java.util.zip.ZipFile: getInputStream, entries
- org.apache.commons.compress.archivers.ArchiveInputStream: getNextEntry
"""

# ---------------------------------------------------------------------------
# Structured sink definitions (Pecker's ClassName#method format)
# These are the authoritative definitions — grep patterns are derived from them.
# ---------------------------------------------------------------------------

STRUCTURED_SINKS = {
    "sqli": {
        # JDBC core
        "java.sql.Statement": ["executeQuery", "executeUpdate", "addBatch", "executeLargeUpdate", "execute"],
        "java.sql.Connection": ["prepareStatement", "prepareCall", "nativeSQL"],
        # JPA
        "javax.persistence.EntityManager": ["createQuery", "createNativeQuery"],
        "jakarta.persistence.EntityManager": ["createQuery", "createNativeQuery"],
        # Spring JdbcTemplate (and subclasses)
        "*.JdbcTemplate": ["batchUpdate", "execute", "update", "queryForList",
                            "queryForObject", "queryForMap", "queryForRowSet", "query"],
        "*.NamedParameterJdbcTemplate": ["batchUpdate", "execute", "update",
                                           "queryForList", "queryForObject", "query"],
        # Hibernate
        "org.hibernate.Session": ["createQuery", "createSQLQuery", "createNativeQuery"],
        "org.hibernate.SharedSessionContract": ["createQuery", "createSQLQuery", "createNativeQuery"],
        # MyBatis-Plus (raw SQL methods)
        "com.baomidou.mybatisplus.core.mapper.BaseMapper": ["selectList", "selectOne"],
        # InfluxDB
        "org.influxdb.InfluxDB": ["query"],
        # PageHelper
        "com.github.pagehelper.PageHelper": ["orderBy", "setOrderBy"],
        # Ebean
        "io.ebean.Database": ["createSqlQuery", "createSqlUpdate"],
        "io.ebean.Ebean": ["createSqlQuery", "createSqlUpdate"],
        # Nutz
        "org.nutz.dao.Dao": ["execute"],
        # ClickHouse
        "ru.yandex.clickhouse.ClickHouseDataSource": ["<init>"],
    },
    "rce": {
        "java.lang.Runtime": ["exec"],
        "java.lang.ProcessBuilder": ["<init>", "start", "command"],
        "javax.script.ScriptEngine": ["eval"],
        # Spring SpEL
        "org.springframework.expression.Expression": ["getValue"],
        "org.springframework.expression.ExpressionParser": ["parseExpression"],
    },
    "xxe": {
        "org.dom4j.DocumentHelper": ["parseText"],
        "org.dom4j.io.SAXReader": ["read"],
        "javax.xml.parsers.DocumentBuilder": ["parse"],
        "javax.xml.parsers.DocumentBuilderFactory": ["newDocumentBuilder"],
        "javax.xml.stream.XMLInputFactory": ["createXMLStreamReader", "createXMLEventReader"],
        "javax.xml.parsers.SAXParser": ["parse"],
        "org.jdom2.input.SAXBuilder": ["build"],
        "org.jdom.input.SAXBuilder": ["build"],
        "javax.xml.transform.Transformer": ["transform"],
        "javax.xml.xpath.XPathExpression": ["evaluate"],
        "javax.xml.bind.Unmarshaller": ["unmarshal"],
        "org.xml.sax.XMLReader": ["parse"],
        "org.apache.commons.digester.Digester": ["parse", "asyncParse"],
        "org.apache.commons.digester3.Digester": ["parse", "asyncParse"],
        "javax.xml.validation.Validator": ["validate"],
        "javax.xml.validation.SchemaFactory": ["newSchema"],
        "org.apache.poi.xssf.extractor.XSSFExportToXml": ["exportToXML"],
        "java.beans.XMLDecoder": ["readObject"],
    },
    "ssrf": {
        "java.net.URL": ["openConnection", "openStream"],
        "java.net.HttpURLConnection": ["connect", "getInputStream"],
        "org.apache.http.client.HttpClient": ["execute"],
        "org.apache.http.impl.client.CloseableHttpClient": ["execute"],
        "org.springframework.web.client.RestTemplate": ["getForObject", "postForObject",
                                                          "exchange", "getForEntity", "postForEntity"],
        "org.springframework.web.reactive.function.client.WebClient": ["get", "post", "put", "delete"],
        "okhttp3.OkHttpClient": ["newCall"],
    },
    "path_traversal": {
        # File I/O constructors
        "java.io.File": ["<init>"],
        "java.io.FileInputStream": ["<init>"],
        "java.io.FileOutputStream": ["<init>"],
        "java.io.FileReader": ["<init>"],
        "java.io.FileWriter": ["<init>"],
        "java.io.RandomAccessFile": ["<init>"],
        # NIO
        "java.nio.file.Paths": ["get"],
        "java.nio.file.Path": ["of", "resolve", "resolveSibling"],
        "java.nio.file.Files": ["readAllBytes", "readAllLines", "readString", "write",
                                "copy", "move", "delete", "deleteIfExists", "exists",
                                "newInputStream", "newOutputStream", "newBufferedReader",
                                "newBufferedWriter", "lines", "walk", "list",
                                "createFile", "createDirectory", "createDirectories"],
        # Servlet
        "javax.servlet.ServletContext": ["getRealPath", "getResource", "getResourceAsStream"],
        "jakarta.servlet.ServletContext": ["getRealPath", "getResource", "getResourceAsStream"],
        # Spring resource
        "org.springframework.core.io.ClassPathResource": ["<init>"],
        "org.springframework.core.io.FileSystemResource": ["<init>"],
        "org.springframework.core.io.UrlResource": ["<init>"],
        "org.springframework.core.io.ResourceLoader": ["getResource"],
        "org.springframework.util.ResourceUtils": ["getFile", "getURL"],
        # Static file serving
        "spark.staticfiles.StaticFilesConfiguration": ["consume"],
        "org.springframework.web.servlet.resource.ResourceHttpRequestHandler": ["handleRequest"],
        # Zip/archive (Zip Slip)
        "java.util.zip.ZipInputStream": ["getNextEntry"],
        "java.util.zip.ZipFile": ["getInputStream", "entries"],
    },
}

# ---------------------------------------------------------------------------
# Sink grep patterns for pre-scanning (zero LLM cost)
# Derived from STRUCTURED_SINKS — kept for backward compatibility and
# fast codebase scanning.
# ---------------------------------------------------------------------------

SINK_GREP_PATTERNS = {
    "sqli": r"executeQuery|executeUpdate|createQuery|\.query\(|\$\{|\.execute\(|JdbcTemplate|createNativeQuery|prepareStatement|prepareCall|addBatch|nativeSQL|createSQLQuery|queryForList|queryForObject|batchUpdate|orderBy|setOrderBy|createSqlQuery|createSqlUpdate",
    "rce": r"Runtime\..*exec|ProcessBuilder|ScriptEngine\.eval|Expression\.getValue|parseExpression|Class\.forName.*invoke",
    "xxe": r"DocumentBuilder|SAXReader|XMLInputFactory|SAXParser|SAXBuilder|Unmarshaller|Transformer\.transform|DocumentHelper|XMLReader|Digester|SchemaFactory|XSSFExportToXml|XMLDecoder",
    "ssrf": r"URL\(|openConnection|HttpClient|RestTemplate|WebClient|OkHttp|openStream|HttpURLConnection",
    "path_traversal": r"new File\(|FileInputStream\(|FileOutputStream\(|FileReader\(|FileWriter\(|RandomAccessFile\(|Paths\.get\(|Path\.of\(|Files\.(read|write|copy|move|delete|exists|newInput|newOutput|lines|walk|list)|getRealPath\(|getResource\(|ClassPathResource\(|FileSystemResource\(|ResourceLoader|staticFile|externalLocation|ZipInputStream|ZipFile",
    "mybatis_dollar": r"\$\{",
}
