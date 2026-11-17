"""Offline, location-preserving document splitting with the pinned LlamaIndex SDK."""

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version


SDK_VERSION = "0.14.26"
PARSER_VERSION = f"llama-index-{SDK_VERSION}-utf8-v1"
MAX_DOCUMENT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Chunk:
    ordinal: int
    start_char: int
    end_char: int
    start_byte: int
    end_byte: int
    text: str
    content_digest: str


def text_digest(text):
    return sha256(text.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _sdk():
    try:
        if version("llama-index-core") != SDK_VERSION:
            raise ValueError(f"Install LlamaIndex {SDK_VERSION} from the integration lock")
        from llama_index.core.node_parser import MarkdownNodeParser, TokenTextSplitter
        from llama_index.core.schema import Document
    except (ImportError, PackageNotFoundError):
        raise ValueError("Install the locked LlamaIndex integration") from None
    return Document, MarkdownNodeParser, TokenTextSplitter


def validate_document(text, file_format):
    if file_format not in ("text", "markdown"):
        raise ValueError("Supported knowledge formats are text and markdown")
    if type(text) is not str or not text.strip() or "\0" in text:
        raise ValueError("Knowledge documents require nonempty UTF-8 text")
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError("Knowledge document exceeds the UTF-8 byte limit")


def _markdown_sections(text, parser, document):
    # MarkdownNodeParser can normalize e.g. a tab after a heading marker. When
    # its output cannot be placed exactly, split the original source directly.
    sections, position = [], 0
    for node in parser.get_nodes_from_documents([document]):
        start, end = node.start_char_idx, node.end_char_idx
        if start is None or end is None or start < position or text[position:start].strip():
            return [(0, text)]
        if text[start:end] != node.text:
            return [(0, text)]
        sections.append((start, node.text))
        position = end
    return sections if sections and not text[position:].strip() else [(0, text)]


def split_document(text, file_format, chunk_bytes):
    """Return exact half-open code-point and UTF-8 byte ranges in the original."""
    validate_document(text, file_format)
    if type(chunk_bytes) is not int or not 16 <= chunk_bytes <= 8192:
        raise ValueError("Knowledge chunk byte limit must be 16–8192")
    Document, MarkdownNodeParser, TokenTextSplitter = _sdk()
    sections = [(0, text)]
    if file_format == "markdown":
        parser = MarkdownNodeParser.from_defaults(include_metadata=False, include_prev_next_rel=False)
        sections = _markdown_sections(text, parser, Document(text=text, id_=text_digest(text)))
    splitter = TokenTextSplitter(
        chunk_size=chunk_bytes, chunk_overlap=0, tokenizer=lambda value: value.encode("utf-8"),
        separator=" ", backup_separators=["\n", "。", "！", "？"], keep_whitespaces=True,
        include_metadata=False, include_prev_next_rel=False,
    )
    chunks = []
    cursor_char, cursor_byte = 0, 0
    for section_start, section in sections:
        parts = splitter.split_text(section)
        if "".join(parts) != section:
            raise ValueError("LlamaIndex output does not match the original document")
        offset = section_start
        for part in parts:
            end = offset + len(part)
            if part.strip():
                start_byte = cursor_byte + len(text[cursor_char:offset].encode("utf-8"))
                end_byte = start_byte + len(part.encode("utf-8"))
                chunks.append(Chunk(len(chunks), offset, end, start_byte, end_byte, part, text_digest(part)))
                cursor_char, cursor_byte = end, end_byte
            offset = end
    if not 1 <= len(chunks) <= 4096:
        raise ValueError("Knowledge document exceeds the chunk count limit")
    return tuple(chunks)
