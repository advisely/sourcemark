# Sourcemark — Architecture

All diagrams are Mermaid and render natively on GitHub. UML-style class, sequence, state, and deployment views follow the component views.

---

## 1. Where Sourcemark sits

The central claim of the architecture is what the dashed boundary shows: **customer content never crosses it.** Only Merkle roots leave.

```mermaid
flowchart LR
    subgraph BOUNDARY["Customer trust boundary — content never leaves"]
        direction TB
        SRC[("Source documents<br/>PDF · DOCX · scans")]
        PARSE["Parser<br/>Docling · Reducto · Unstructured · Azure DI"]
        STORE[("Retrieval store<br/>pgvector · Qdrant · Weaviate<br/>Elastic · Mongo · Azure AI Search")]
        APP["Application or agent<br/>LLM answer"]

        ANCHOR["Sourcemark ANCHOR<br/><i>library, ingest-time</i>"]
        EMIT["Sourcemark EMIT<br/><i>library, query-time</i>"]

        SRC --> PARSE
        PARSE -->|"chunks + page/bbox/byte-range"| ANCHOR
        PARSE -->|"chunks + embeddings"| STORE
        ANCHOR -->|"writes leaf_hash,<br/>proof paths as metadata"| STORE
        STORE -->|"top-k results"| EMIT
        EMIT -->|"results + receipts"| APP
    end

    LOG[("Transparency log<br/>RFC 6962 · Trillian or Rekor<br/><b>holds only 32-byte roots</b>")]
    AUDITOR["Auditor · regulator · counterparty<br/><i>no access to any of the above</i>"]

    ANCHOR -.->|"corpus_root only"| LOG
    APP -->|"answer + receipt"| AUDITOR
    LOG -.->|"public signed tree head"| AUDITOR
    AUDITOR --> VERIFY["Sourcemark VERIFY<br/><i>open source, offline</i>"]

    style ANCHOR fill:#1f6f5c,color:#fff,stroke:#1f6f5c
    style EMIT fill:#1f6f5c,color:#fff,stroke:#1f6f5c
    style VERIFY fill:#1f6f5c,color:#fff,stroke:#1f6f5c
    style BOUNDARY fill:none,stroke-dasharray: 6 4
    style LOG fill:#e8efec,stroke:#1f6f5c
```

The auditor verifies using only the receipt and a public key. Every arrow into `VERIFY` originates outside the system under audit — which is the entire point, and the property a database cannot have about itself.

---

## 2. Component view

```mermaid
flowchart TB
    subgraph SM["Sourcemark"]
        direction LR

        subgraph A["ANCHOR · ingest"]
            A1["Coordinate normalizer<br/>parser-specific adapters"]
            A2["Leaf builder<br/>HMAC commitment + CBOR coords"]
            A3["Merkle tree builder<br/>per document version"]
            A4["Batch submitter<br/>corpus root → log"]
            A5["Metadata writer<br/>store-specific adapters"]
            A1 --> A2 --> A3 --> A4
            A3 --> A5
        end

        subgraph E["EMIT · query"]
            E1["Retriever wrapper<br/>pass-through, no re-ranking"]
            E2["Receipt assembler"]
            E3["COSE signer<br/>C2PA manifest profile"]
            E4["Delivery<br/>SDK · HTTP header · MCP annotation"]
            E1 --> E2 --> E3 --> E4
        end

        subgraph B["BIND · optional"]
            B1["Span matcher<br/>QUOTED, deterministic"]
            B2["Entailment scorer<br/>SUPPORTED/INFERRED/UNSUPPORTED"]
        end

        subgraph V["VERIFY · offline, open source"]
            V1["Content binding check"]
            V2["Leaf reconstruction"]
            V3["Inclusion proof fold"]
            V4["Tree-head signature check"]
            V5["Ordering check<br/>commit precedes answer"]
            V6["Source re-derivation<br/>optional, needs original file"]
            V1 --> V2 --> V3 --> V4 --> V5 --> V6
        end
    end

    B --> E2
    A5 -.->|"metadata read back"| E1
    E4 -.->|"receipt travels with the answer"| V1

    style A fill:#f2f6f4,stroke:#1f6f5c
    style E fill:#f2f6f4,stroke:#1f6f5c
    style B fill:#faf7f2,stroke:#b4682f,stroke-dasharray: 4 3
    style V fill:#1f6f5c,color:#fff,stroke:#1f6f5c
```

`BIND` is drawn dashed and in a different hue because it is the only component producing a *scored* rather than a *proven* claim. That visual separation mirrors the data-model separation in `SPEC.md §5`.

---

## 3. Ingest sequence

```mermaid
sequenceDiagram
    autonumber
    participant J as Ingestion job
    participant P as Parser
    participant AN as Anchor
    participant KMS as KMS
    participant DB as Retrieval store
    participant LOG as Transparency log

    J->>P: parse(document.pdf)
    P-->>J: chunks + page/bbox/byte_range
    J->>AN: anchor(doc_version, chunks)
    AN->>KMS: mint version_key for doc_version
    KMS-->>AN: salt_ref (handle to the version key)
    loop each chunk
        AN->>AN: salt = HKDF(version_key, dv_id, chunk_id)
        AN->>AN: commitment = HMAC-SHA-256(salt, text)
        AN->>AN: leaf = H(0x00 ‖ CBOR[ids, coords, commitment])
    end
    AN->>AN: build doc Merkle tree → doc_root
    AN->>DB: write leaf_hash, document path, salt_ref
    Note over AN,LOG: batching window (default 60s)
    AN->>AN: build corpus tree over doc_roots
    AN->>LOG: submit corpus_root (32 bytes, nothing else)
    LOG-->>AN: log_entry_id + signed tree head
    AN->>DB: write log_entry_id, corpus path, tree sizes
    Note over J,DB: chunk is now anchored and queryable
```

The batching window is the one latency knob that matters: a chunk is not verifiable until its root is logged. Sixty seconds is the default; synchronous submission is available where a corpus is small or an SLA demands it.

---

## 4. Query and independent verification

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant APP as Application / agent
    participant EM as Emit
    participant DB as Retrieval store
    participant LLM as Model
    actor AUD as Auditor

    U->>APP: question
    APP->>EM: search(query, k=5)
    EM->>DB: native query (unmodified)
    DB-->>EM: chunks + anchoring metadata
    EM->>EM: assemble + COSE-sign receipts
    EM-->>APP: results + receipts
    APP->>LLM: generate(question, chunks)
    LLM-->>APP: answer with citations
    opt Bind enabled
        APP->>EM: score(answer spans, chunks)
        EM-->>APP: support class + score, proven=false
    end
    APP-->>U: answer + receipts

    Note over AUD: months later, no system access
    U->>AUD: hands over answer + receipt + original PDF
    AUD->>AUD: sourcemark verify receipt.cbor --log-key pub.pem --source original.pdf
    AUD->>AUD: check tree-head signature, and that its key hashes to log_id
    AUD->>AUD: fold chunk → doc_root → corpus_root → signed root
    AUD->>AUD: re-read byte_range from the PDF, recompute the HMAC
    AUD-->>AUD: CUSTODY VERIFIED · committed 2026-03-14, before answer
```

Note what the auditor never does: contact the vendor, log into a console, or ask anyone to run a query. Every step after the handover is local arithmetic.

---

## 5. Receipt data model (UML class diagram)

```mermaid
classDiagram
    class Receipt {
        +string receipt_version
        +string kind
        +verify() VerificationOutcome
    }

    class Custody {
        <<cryptographic · binary>>
        +check() VerificationOutcome
    }

    class Support {
        <<statistical · scored>>
        +SupportClass class
        +float score
        +string scorer
        +float threshold
        +bool proven = false
    }

    class Source {
        +string document_id
        +string document_version_id
        +string source_uri
        +string content_hash
        +datetime committed_at
    }

    class Location {
        +int page
        +string paragraph
        +int[4] bbox
        +int[2] byte_range
    }

    class Derivation {
        +string chunk_id
        +string parser
        +string salt_ref
        +bytes content_commitment
        +Opening opening
    }

    class Opening {
        <<salt · or · erased tombstone>>
        +bytes salt
        +bool erased
    }

    class Proof {
        +string leaf_hash
        +MerkleFold document
        +MerkleFold corpus
        +LogFold log
    }

    class MerkleFold {
        +int leaf_index
        +int tree_size
        +string[] path
        +string root
        +fold() string
    }

    class LogFold {
        +string url
        +string log_id
        +string entry_id
        +int leaf_index
        +int tree_size
        +string[] path
        +string root_hash
        +bytes signed_tree_head
    }

    class QueryContext {
        +string query_id
        +string retriever
        +datetime retrieved_at
        +string policy_ref
    }

    class SupportClass {
        <<enumeration>>
        QUOTED
        SUPPORTED
        INFERRED
        UNSUPPORTED
    }

    Receipt "1" *-- "1" Custody
    Receipt "1" o-- "0..1" Support : optional
    Receipt "1" *-- "1" QueryContext
    Custody "1" *-- "1" Source
    Custody "1" *-- "1" Location
    Custody "1" *-- "1" Derivation
    Custody "1" *-- "1" Proof
    Derivation "1" *-- "1" Opening
    Proof "1" *-- "2" MerkleFold : document, corpus
    Proof "1" *-- "1" LogFold
    Support ..> SupportClass

    note for Support "proven is always false.\nA score is never a proof."
    note for Custody "Composition, not aggregation:\na receipt without custody\nis not a receipt."
    note for Opening "A union, not an optional field.\nErased must be stated, not\nindistinguishable from omitted."
    note for Proof "Three folds. Two leave\ncorpus_root attached to\nnothing anyone signed."
```

`Support` is an aggregation and optional; `Custody` is a composition and mandatory. A Sourcemark receipt with no support score is still a valid receipt. A receipt with no custody proof is not a receipt at all — it is a citation, which is what we are replacing.

---

## 6. Chunk lifecycle (UML state diagram)

```mermaid
stateDiagram-v2
    [*] --> Parsed : parser emits coords
    Parsed --> Leafed : leaf computed
    Leafed --> Pending : in current batch window
    Pending --> Anchored : corpus_root logged
    Pending --> Failed : log unreachable
    Failed --> Pending : retry with backoff

    Anchored --> Anchored : queried, receipt issued

    Anchored --> Superseded : new document version ingested
    Superseded --> Superseded : historical receipts still verify

    Anchored --> Erased : erasure request, salt destroyed
    Superseded --> Erased : erasure request, salt destroyed
    Erased --> [*]

    note right of Pending
        Queryable but NOT verifiable.
        Emit returns receipt_unavailable
        with reason "pending anchor".
    end note

    note right of Erased
        Tree unchanged. Leaf unopenable.
        Verification returns ERASED,
        which is not INVALID.
    end note
```

The distinction between `Failed` and `Pending` and between `Erased` and an invalid proof is the whole reliability story. A system that quietly returns a stub receipt in any of these states is worse than one with no receipts, because it converts an absence of evidence into false evidence.

---

## 7. Verification outcomes

```mermaid
stateDiagram-v2
    direction LR
    [*] --> Checking
    Checking --> VERIFIED : all checks pass
    Checking --> ERASED : salt destroyed, tree intact
    Checking --> PENDING : leaf not yet in a logged root
    Checking --> TAMPERED : content hash mismatch
    Checking --> FORGED : inclusion proof does not fold to root
    Checking --> BACKDATED : log entry postdates the answer
    Checking --> UNSIGNED : tree-head signature invalid

    VERIFIED --> [*]
    ERASED --> [*]
    PENDING --> [*]
    TAMPERED --> [*]
    FORGED --> [*]
    BACKDATED --> [*]
    UNSIGNED --> [*]
```

Seven terminal outcomes, not two. `TAMPERED`, `FORGED`, `BACKDATED`, and `UNSIGNED` are distinct failures that point at different culprits — the storage layer, the receipt issuer, the timeline, and the log operator respectively. A boolean would hide which one occurred.

---

## 8. Deployment topologies (UML deployment view)

```mermaid
flowchart TB
    subgraph M1["Embedded — default"]
        direction LR
        M1A["App process<br/>+ sourcemark lib"] --> M1B[("Customer store")]
        M1A -.->|"roots"| M1C[("Public log<br/>or Rekor")]
    end

    subgraph M2["Sidecar — regulated"]
        direction LR
        M2A["App process<br/>+ sourcemark lib"] --> M2B[("Customer store")]
        M2A --> M2D["Submitter sidecar<br/>key custody · batching"]
        M2D -.->|"roots"| M2C[("Customer Trillian")]
    end

    subgraph M3["Air-gapped — classified"]
        direction LR
        M3A["App process<br/>+ sourcemark lib"] --> M3B[("Customer store")]
        M3A --> M3D["Local log"]
        M3D -.->|"tree heads on media"| M3E["Offline witness"]
    end

    style M1 fill:#f2f6f4,stroke:#1f6f5c
    style M2 fill:#f2f6f4,stroke:#1f6f5c
    style M3 fill:#f2f6f4,stroke:#1f6f5c
```

The same library binary serves all three. The topology changes who holds the log and the signing key, never what the customer has to install or how their retrieval works.

---

## 9. What changed from v1 — the architectural diff

```mermaid
flowchart TB
    subgraph V1["ScaleDB v1 — replace the stack"]
        direction TB
        V1A["Application"] --> V1B["ScaleDB engine<br/>storage · MVCC · WAL<br/>HNSW · BM25 · RRF<br/>SQL planner · parser pipeline<br/>Raft · sharding · RBAC"]
        V1B --> V1C[("Owns all customer data")]
        V1D["Postgres · Mongo · Elastic<br/>Pinecone · Weaviate"] -.->|"COMPETITOR<br/>rip and replace"| V1B
    end

    subgraph V2["Sourcemark v2 — add a layer"]
        direction TB
        V2A["Application"] --> V2B["Sourcemark<br/>anchor · emit · verify"]
        V2B --> V2C[("Postgres · Mongo · Elastic<br/>Pinecone · Weaviate<br/>customer keeps their data")]
        V2D["Docling · Reducto<br/>Unstructured · Azure DI"] -->|"PARTNER<br/>supplies coordinates"| V2B
        V2B -->|"PARTNER<br/>supplies evidence"| V2E["Credo AI · Vanta<br/>watsonx.governance"]
    end

    style V1B fill:#a6332e,color:#fff,stroke:#a6332e
    style V2B fill:#1f6f5c,color:#fff,stroke:#1f6f5c
    style V1 stroke:#a6332e,stroke-dasharray: 4 3
    style V2 stroke:#1f6f5c
```

Same underlying insight — provenance belongs at the retrieval layer — expressed as a component that every incumbent wants to buy rather than an engine every incumbent has to beat.

---

## 10. Scale envelope

| Dimension | Figure | Note |
|---|---|---|
| Storage overhead per chunk | 300–600 bytes | `leaf_hash` 32B, commitment 32B, document path ~20×32B at 1M chunks, coords. The corpus and log proofs are stored once per document version and once per batch, not per chunk; the salt is derived, not stored |
| Overhead on a 10M-chunk corpus | ~4–6 GB | In the customer's existing store, in existing columns |
| Anchor throughput | ~50k leaves/sec/core | SHA-256 bound; Merkle build is linear |
| Emit added latency | < 2 ms p95 | Metadata is already in the result row; signing is one Ed25519 op |
| Verify time | < 5 ms | ~20 hashes plus one signature check, offline |
| Bytes submitted to the log | 32 per batch window | Roots only |

The design is deliberately cheap on the hot path. Emit adds a signature, not a network call — anything that made query-time verification depend on log availability would have made retrieval less reliable in exchange for making it more provable, which is a bad trade nobody would take.
