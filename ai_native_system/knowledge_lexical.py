"""Chinese lexical candidates on the same permission-filtered chunk set as vectors."""

import re
from dataclasses import dataclass
from hashlib import sha256
from itertools import islice, product
from unicodedata import normalize


_QUOTES = re.compile(r'"([^"]+)"|“([^“”]+)”|「([^「」]+)」|『([^『』]+)』')
_NUMBER = r"(?:[0-9]+(?:[.-][0-9]+)*|[〇零一二两三四五六七八九十百千万亿]+)"
_CLAUSE = re.compile(rf"第\s*({_NUMBER})\s*([条款项章节])((?:\s*之\s*{_NUMBER})*)")
_HAN_DIGITS = "零一二三四五六七八九"
_HAN_UNITS = {"十": 10, "百": 100, "千": 1000}
_TERM_LIMIT = 128


@dataclass(frozen=True)
class LexicalQuery:
    text: str
    literals: tuple[str, ...]
    clauses: tuple[str, ...]
    standalone_clause: bool

    @property
    def requires_literal(self):
        return self.standalone_clause or bool(self.literals)


def _han_ordinal(number):
    parts = []
    for digit, unit in zip(f"{number:04d}", ("千", "百", "十", "")):
        if digit != "0":
            parts.append(_HAN_DIGITS[int(digit)] + unit)
        elif parts and parts[-1] != "零":
            parts.append("零")
    written = "".join(parts).rstrip("零") or "零"
    return written[1:] if written.startswith("一十") else written


def _ordinal_number(written):
    if written.isascii() and written.isdecimal():
        return int(written) if len(written) <= 4 else None
    if any(char not in _HAN_DIGITS + "十百千" for char in written) or len(written) > 7:
        return None
    number, digit = 0, 0
    for char in written:
        if char in _HAN_UNITS:
            number += (digit or 1) * _HAN_UNITS[char]
            digit = 0
        else:
            digit = _HAN_DIGITS.index(char)
    number += digit
    if number <= 9999:
        canonical = _han_ordinal(number)
        if canonical == written or canonical.startswith("十") and written == "一" + canonical:
            return number
    return None


def _number_spellings(ordinal):
    yield ordinal
    number = _ordinal_number(ordinal.replace("两", "二").replace("〇", "零"))
    if number is not None:
        han = _han_ordinal(number)
        yield str(number)
        yield han
        if han.startswith("十"):
            yield "一" + han


def _clause_keys(match):
    ordinal, unit, suffix = match.groups()
    numbers = (ordinal, *re.findall(_NUMBER, suffix))
    variants = product(*(tuple(dict.fromkeys(_number_spellings(number))) for number in numbers))
    for primary, *subclauses in islice(variants, _TERM_LIMIT):
        key = f"c:第{primary}{unit}" + "".join(f"之{suffix}" for suffix in subclauses)
        yield "h:" + sha256(key.encode("utf-8")).hexdigest() if len(key) > 128 else key


def parse_lexical_query(query):
    text = normalize("NFKC", query).strip()
    literals = tuple(
        literal for match in _QUOTES.finditer(text)
        if (literal := next(part for part in match.groups() if part is not None).strip())
    )
    words = _QUOTES.sub(lambda match: next(part for part in match.groups() if part is not None), text)
    standalone = _CLAUSE.fullmatch(words)
    clauses = {key for match in _CLAUSE.finditer(words) for key in _clause_keys(match)}
    return LexicalQuery(words, literals, tuple(sorted(clauses))[:_TERM_LIMIT], standalone is not None)


def lexical_rows(connection, plan, *, projection, source_join, predicate, parameters, limit,
                 projection_parameters=()):
    """Rank indexed term matches after applying the shared document predicate."""
    tenant, index_id = parameters[:2]
    return connection.execute(
        f"""WITH request AS MATERIALIZED (
                SELECT ai_native.knowledge_lexical_normalize_v1(?::text) AS phrase,
                       ARRAY(SELECT ai_native.knowledge_lexical_normalize_v1(literal)
                             FROM unnest(?::text[]) AS literal) AS literals,
                       ?::text[] || ARRAY(SELECT t.term FROM ai_native.knowledge_lexical_terms_v1(?::text, true) t
                                          ORDER BY t.term COLLATE "C" LIMIT ?) AS terms
            ), matched AS (
                SELECT p.chunk_id, count(*) AS term_score,
                       count(*) FILTER (WHERE left(p.term, 2) = 'c:') AS clause_score
                FROM ai_native.knowledge_lexical_postings p
                WHERE p.tenant=? AND p.index_id=? AND p.term=ANY((SELECT terms FROM request)::text[])
                GROUP BY p.chunk_id
            )
            SELECT {projection} {source_join}
            JOIN matched ON matched.chunk_id = c.chunk_id
            CROSS JOIN request
            WHERE {predicate}
              AND NOT EXISTS (
                  SELECT 1 FROM unnest(request.literals) AS literal
                  WHERE strpos(ai_native.knowledge_lexical_normalize_v1(c.text), literal) = 0
              )
            ORDER BY strpos(ai_native.knowledge_lexical_normalize_v1(c.text), request.phrase) > 0 DESC,
                     matched.clause_score DESC, matched.term_score DESC, distance, c.document_id, c.chunk_id
            LIMIT ?""",
        (plan.text, list(plan.literals), list(plan.clauses), "" if plan.standalone_clause else plan.text,
         _TERM_LIMIT, tenant, index_id, *projection_parameters, *parameters, limit),
    ).fetchall()
