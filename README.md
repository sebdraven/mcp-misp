# mcp-misp

An MCP server in Go exposing a [MISP](https://www.misp-project.org/) instance to
CTI workflows. Two transports: **stdio** (default, for a local client such as
Claude Desktop) and **streamable HTTP** (for remote or containerised
deployment). Built on the official
[`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk).

It is written for CERT/CSIRT teams running their own instance. Three things
shape it:

- **Warninglist verdicts are not optional.** Every value this server returns
  carries whether the instance considers it a known false positive, and every
  answer says how much of the warninglist set actually took part in deciding.
- **Volume is the central constraint.** A MISP event can carry tens of thousands
  of attributes. Nothing returns a raw MISP object, everything is projected,
  capped and paginated, and bulk results go to disk instead of into the model's
  context.
- **No instance is assumed.** No taxonomy, no custom object, no tagging
  convention is hard-coded. Anything organisation-specific is discovered at run
  time.

The MISP client is written from scratch in this repository. No existing Go MISP
library is used, and nothing depends on PyMISP or on any Python at all.

## Tools

Eleven tools: seven read, four write. The write tools exist only when the server is
started with `MISP_READONLY=false` — not disabled, **absent from the tool list**,
so a client cannot offer what it never saw.

| Tool | Answers |
| --- | --- |
| `misp_search` | unified search over `restSearch`: value, attribute type, category, tags, date range, `to_ids`, published state, organisation |
| `misp_event` | one event by id or UUID: header plus one page of attributes |
| `misp_ioc_context` | everything this instance knows about one IOC: events, `to_ids`, sightings, tags, organisations, warninglist verdict |
| `misp_warninglist_check` | check arbitrary values against the enabled warninglists, or inventory the lists |
| `misp_taxonomies` | the taxonomies and tags this instance actually carries |
| `misp_object_templates` | the object templates this instance carries, and one template's relations |
| `misp_describe_instance` | version, valid attribute types and categories, organisations, enabled warninglist count, ceilings |
| `misp_add_attribute` | create one attribute — **`MISP_READONLY=false` only** |
| `misp_create_event` | create an event — **`MISP_READONLY=false` only** |
| `misp_add_objects` | add several objects and their references in one call — **`MISP_READONLY=false` only** |
| `misp_tag` | attach tags to an event or attribute — **`MISP_READONLY=false` only** |

There is **no publish tool and no delete tool**, no tag removal, and no way to
modify an existing object or attribute. The write surface is creation only, and
nothing writes under the default configuration.

### `misp_search`

`value`, `type[]`, `category[]`, `tags[]`, `event_tags[]`, `org`, `from`, `to`,
`to_ids`, `published`, `returns`, `exclude_warninglisted`, `fields[]`, `limit`,
`cursor`, `out_dir`.

`returns` is `attributes` (default) or `events`. Attribute rows carry their
parent event — id, uuid, info, date, organisation, event tags — so a row is
readable on its own. That is deliberate: an attribute with no event context
forces one `misp_event` call per result, which is the volume problem this server
exists to bound.

`from` and `to` accept `YYYY-MM-DD` or a relative window (`30d`, `12h`, `4w`,
`6m`). Relative windows are resolved to an absolute date by this server, because
MISP accepts them reliably on timestamp filters but not on the event-date
filters used here.

### `misp_event`

`event` (numeric id or UUID), `fields[]`, `attribute_fields[]`,
`attribute_type[]`, `attribute_category[]`, `to_ids_only`, `attribute_limit`,
`attribute_cursor`, `out_dir`.

Two bounded calls: `POST /events/restSearch` with `metadata=1` for the header,
then `POST /attributes/restSearch` for a page of attributes. `GET /events/view`
is never used — on a large event it serialises every attribute, which is exactly
the failure mode this server is built to avoid.

`attribute_count` on the header is the real size of the event. Compare it with
`attributes_returned` to know how much was not read.

Objects are not returned as objects. Group attributes with the `object_id` and
`object_relation` attribute fields.

### `misp_ioc_context`

`value`, `type[]`, `max_events`, `include_sightings`, `out_dir`.

One attribute search carrying sightings and event tags, plus one warninglist
check. The warninglist verdict is returned **even when the value appears in no
event**, because "unknown here and on an exclusion list" is a different answer
from "unknown here".

The `aggregate` block (`event_count`, `to_ids_true`, `to_ids_false`,
`first_seen`, `last_seen`, tag counts, organisations) covers every attribute
read, even when the event list itself was trimmed. Count from the aggregate,
read from the event list.

### `misp_warninglist_check`

`values[]`, `type`. With no values it inventories the enabled lists instead,
with each one's matching type and the attribute types it applies to.

### `misp_taxonomies`

`namespace`, `tag_search`, `include_predicates`, `limit`, `cursor`, `out_dir`.

Disabled taxonomies are listed and marked rather than hidden — their tags may
still be attached to older events. Tags outside any taxonomy are listed too:
those are local conventions, and they are often where an organisation puts what
matters to it.

`include_predicates` expands one named taxonomy and requires `namespace`.
Expanding them all is one call per taxonomy and tens of thousands of entries.

### `misp_object_templates`

`template`, `search`, `limit`, `cursor`.

What `misp_describe_instance` is to attributes, this is to objects. `misp_add_objects`
is unusable without it: relation names are template-specific, and a guessed one
either fails validation or lands as free text.

With no argument it inventories the instance's templates. With a template name
(`file`, `x509`, …) it returns every relation with its MISP attribute type,
whether it accepts several values, and the template's own constraints.

**MISP object templates declare no deduplication key.** The format carries
exactly two constraints — `required` (all must be present) and `required_one_of`
(at least one must be) — and nothing else. Verified against the 408 definitions
bundled with misp-objects. Whether an identical object is rejected or duplicated
is decided at write time; see `on_duplicate` below.

Templates come from the instance, never from a table baked into this server: a
deployment can carry custom templates, and template versions move.

### `misp_describe_instance`

`include_type_mapping`. This is what makes instance neutrality workable: the
attribute type names and organisation names valid here are the ones
`misp_search` expects, and guessing them is how one deployment's conventions end
up hard-coded into every query. Each lookup degrades on its own — an API key
lacking one permission still gets the rest, and what failed is named in `notes`.

### Write tools

`misp_add_attribute` takes `event`, `type`, `value`, `category`, `comment`,
`to_ids`, `distribution`, `tags[]`, `allow_warninglisted`. The value is checked
against the warninglists **before** anything is written; a hit refuses the
creation and the refusal names the list and the engine that decided.
`allow_warninglisted=true` overrides it. Tags are applied after the attribute
exists, and a tag failure is reported without undoing the creation.

`misp_create_event` takes `info`, `distribution`, `sharing_group_id`, `date`,
`threat_level`, `analysis`, `tags[]`.

**`distribution` is required and is given by name**, never as a number:
`your_organisation_only`, `this_community`, `connected_communities`,
`all_communities`, `sharing_group`. MISP encodes these 0-4, and a caller passing
`3` in the belief that it restricts sharing publishes to every connected
community — the number says nothing, the name does. There is no default: on a
CSIRT instance the instance-wide default can be `all_communities`, and a badly
distributed event is a sharing incident rather than a typo.

The event is created **unpublished**, and `published` is neither a parameter nor
a field in the payload sent to MISP. Publishing stays a human decision in the
MISP interface, for the same reason there has never been a publish tool.

`misp_add_objects` takes `event`, `objects[]`, `references[]`, `on_duplicate`,
`allow_unknown_relations`, `allow_warninglisted`. It is documented in full below.

`misp_tag` takes `target` (`event` or `attribute`), `id` (numeric or UUID) and
`tags[]`. **Adding only.** There is no removal tool: `tlp:` and `PAP:` tags
drive how MISP distributes data, so removing one is a sharing decision dressed
as an annotation. If removal is ever added it must refuse those two namespaces
outright.

## Batched object ingestion

`misp_add_objects` exists so that a whole analysis lands as one linked graph. An
APK, its x509 certificate, its C2 domains and its permissions go in a single
call, with the references that join them — not ten calls with a uuid carried by
hand between each.

Each object may declare a local `ref`, and `references[]` joins those refs, so
objects created in the same call can be linked without knowing any uuid in
advance. A reference endpoint may also be the uuid of an object already in the
event.

### Validation happens in two phases

**Phase 0** resolves one template per *distinct* template name in the batch, not
one per object, and caches it.

**Phase 1 validates the whole batch and writes nothing.** Every problem is
collected, then the entire batch is refused with per-object, per-relation
detail. There is no partial creation on a validation error.

| Checked | Loosened by `allow_unknown_relations` |
| --- | --- |
| the template exists on this instance | no |
| every relation is declared by the template | **yes** |
| the attribute type matches the template's `misp-attribute` | no |
| a relation marked `multiple: false` receives one value | no |
| every relation in `required` is present | no |
| at least one relation in `required_one_of` is present | no |
| every reference endpoint resolves to a batch `ref` or a uuid | no |
| batch, per-object value and reference ceilings | no |
| every value of the batch against the warninglists, in one call | `allow_warninglisted` |

A warninglist hit refuses the batch naming the object, the relation, the value,
the list **and the engine that decided** — the same instance/local divergence,
and the same message, as `misp_add_attribute`.

**Phase 2 writes** in a fixed order: objects first, in batch order, collecting
each `ref`'s uuid; then references, once every target exists.

### `allow_unknown_relations` will not coerce an IOC

A relation the template does not declare still needs a MISP attribute type to be
written. With `allow_unknown_relations` it is written as `text` and reported in
`coerced_relations`.

**Except when the value looks like something MISP correlates on.** A hash, an IP,
a CIDR, a domain, a URL or an email written as `text` sits in the database
invisible to every pivot — intel written and lost, which is worse than a
refusal. Those are refused even with the flag set, and the refusal names the
template relation that would have worked when one exists:

> value looks like sha256 and would be written as free text, which MISP never
> correlates on; allow_unknown_relations does not cover this — use relation
> "sha256", which template "file" declares as sha256

### Duplicates: what MISP actually does

`POST /objects/add/{event_id}` takes a `breakOnDuplicate` parameter, passed as a
CakePHP named path segment rather than a query string:

- **absent** → MISP creates the object **even if an identical one already exists**
  in the event. That is the server-side default.
- **`breakOnDuplicate:1`** → MISP compares the object's attribute set against the
  existing objects and **rejects** on a match. PyMISP documents this as
  potentially slow.

There is no merge and no update: either a duplicate or a rejection.

This server **always sends the parameter explicitly** and never lets the
instance's setting decide. `on_duplicate` defaults to `reject`, so a batch
replayed after a network failure does not double the APK's `file` object.

A duplicate rejection is an expected outcome, not a failure: it is recorded
under `duplicates`, the batch **carries on**, and any reference touching the
rejected object is listed in `not_attempted` with its reason. That is what makes
a re-run useful — it creates what is still missing and tells you which links
could not be made.

### There is no rollback

This server has no delete, and this lot did not add one through the back door.
When a genuine write error occurs after validation, writing stops and the answer
is exact:

| Field | |
| --- | --- |
| `created_objects` | ref, template, uuid, id, attribute count |
| `created_references` | both endpoints, their uuids, and the relationship type written |
| `duplicates` | objects the instance refused as already present |
| `failed_at` | stage, index, ref, and the instance's error |
| `not_attempted` | everything left untouched, named |

A half-written batch whose stopping point is known is recoverable. One whose
stopping point is not, is not.

### Relationship types are usually unvalidated

MISP seeds its object-relationship vocabulary from misp-objects into a table,
but **exposes no documented REST index for it, and stores `relationship_type` as
a free-text column**. This server probes the instance once per hour; when the
probe finds nothing — which is the expected case today — references are written
unchecked.

Because a typo is then accepted silently and yields `contains` and `contain`
living side by side in the same event, every answer in that case carries:

- `relationship_type_validated: false`,
- the exact string written for **each** reference, in `created_references`,
- the distinct values in `unvalidated_relationship_types`,
- and a note saying so — **on every call**, not only the first.

Hard-coding the 313 relationship names would make validation possible, and is
excluded for the same reason as hard-coding templates: this server runs against
instances it has never seen.

## Warninglists

This is the part that differs from the Python MCP servers around, so it is
documented in full.

### Which engine decides

| Path | Used when | Reported as |
| --- | --- | --- |
| Instance | `POST /warninglists/checkValue` answers | `engine: instance` |
| Local fallback | that endpoint is absent or forbidden | `engine: local` |

The instance path is preferred, and it is not a fallback arrangement for
convenience: `checkValue` runs **MISP's own matching engine**, so the verdict
cannot drift from what the instance itself would enforce. `cidr`, `hostname`,
`substring`, `string` and `regex` semantics stay MISP's.

An endpoint that answers 404 or 403 is remembered for ten minutes — an instance
that does not expose it will not start exposing it between two searches. A 503
or a timeout is **not** remembered: it says nothing about whether the endpoint
exists.

`exclude_warninglisted` is separate. It sets `enforceWarninglist` on
`restSearch`, so the instance drops warninglisted attributes before this server
ever sees them. See the caveat below before using it.

### Coverage

Every answer carrying warninglist information also carries a report:

| Field | Meaning |
| --- | --- |
| `engine` | `instance`, `local` or `none` |
| `coverage` | `complete`, `partial` or `unavailable` |
| `uncovered_lists` | enabled lists that did not take part, or took part only in part |
| `loaded_entries` / `loaded_bytes` | size of the local index, when the local engine answered |
| `note` | why coverage is not complete |

**A clean result under anything but `coverage: complete` means "no hit was
seen", never "there is no hit".** That distinction is the whole point of the
report, and it is why an unavailable check returns no per-value verdicts at all
rather than a set of `hit: false`.

### The local fallback engine

Implemented per matching type, with a test per type:

| Type | Semantics |
| --- | --- |
| `string` | exact match, case-insensitive |
| `substring` | the entry is contained in the value |
| `hostname` | the value is reduced to a host (scheme, port, path, userinfo stripped) and matched against itself and every parent domain — one entry for `example.com` covers `mail.corp.example.com`, and `example.com.evil.net` does **not** match |
| `cidr` | IPv4 and IPv6 prefix containment; a bare address becomes a /32 or /128, and families never cross |
| `regex` | see the RE2 divergence below |

An unknown matching type is **not** guessed at. The list goes to
`uncovered_lists` and produces no hits.

### Divergence: `valid_attributes`

Each warninglist declares the attribute types it applies to. The local engine
honours that; `checkValue` on the instance does **not**.

The local engine is therefore sometimes *stricter* than the instance. On the
read path that is the safe direction. **On the write path it is visible**: the
local engine can refuse an `misp_add_attribute` that the MISP web UI would have
accepted. This is why the refusal message names the engine that decided:

> not created: "1.1.1.1" matches warninglist(s) "Public DNS resolvers". Decided
> by this server's local fallback engine, because the instance does not expose
> POST /warninglists/checkValue. The fallback also applies each list's
> valid_attributes, which the instance's own check does not, so this value may be
> accepted through the MISP web UI. Pass allow_warninglisted=true to create it
> anyway.

Without that sentence the user has a value that works in one place and not the
other, and no way to tell why.

### Divergence: PCRE vs RE2

MISP evaluates `regex` warninglists with PCRE. Go's `regexp` is RE2, which has
no lookaround and no backreferences. An entry using one of those does not
compile here.

Such entries are **dropped and the list is reported in `uncovered_lists`**. They
are not silently skipped, because a silently skipped pattern turns a real hit
into a clean answer — the exact failure this server is meant to prevent. This
only affects the local fallback; on the instance path, PCRE is evaluated by MISP
as usual.

### Memory budget

The local index is built lazily on first use — never at startup, because
blocking startup on a slow instance is a defect of its own.

`MISP_WARNINGLIST_MAX_ENTRIES` (default 200 000) is a budget **in number of
entries, not in bytes**. Entries are the only figure available before
downloading anything (`warninglist_entry_count` in `/warninglists/index`), which
is what lets an oversized list be skipped without being fetched. Lists are
loaded smallest-first, so one half-million-entry list cannot consume the whole
budget and leave every small, high-signal list unloaded.

An entry count is not a memory cost: a `/24` and a long substring do not weigh
the same. The report therefore carries both `loaded_entries` and
`loaded_bytes` — set the budget in entries, then read the bytes to calibrate it.

Lists skipped for budget, lists that failed to download, lists with an unknown
matching type and lists with uncompilable regexes all end up in
`uncovered_lists`, and `coverage` becomes `partial`.

## Volume controls

- **Hard ceilings**, enforced server-side. `MISP_MAX_RESULTS` can only *lower*
  them. `misp_describe_instance` reports the ones in force.
- **Mandatory projection.** No tool returns a raw MISP object and there is no
  `include_raw`. `fields` replaces the default set; an unknown field name is an
  error listing the valid ones, because a silently ignored field looks exactly
  like an empty result. The warninglist verdict cannot be projected away.
- **Byte ceiling** (256 KiB by default) as a last line of defence: the count
  limits bound the number of rows, but an attribute comment has no bound of its
  own. A trimmed response sets `truncated` and the `results_truncated` flag.
- **Opaque cursors.** `next_cursor` carries a fingerprint of the query it was
  issued for and is refused against different filters, so a cursor cannot be
  replayed to page through a set it did not come from.
- **`out_dir`** on every bulk tool: rows are written as JSONL plus a manifest
  recording the query, the instance and the counts, and only paths and a summary
  come back.

### Why the last page can be empty

MISP paginates `restSearch` by `page` × `limit` with no offset parameter. Asking
for `limit + 1` rows to detect a following page would make the next page start
one record past where this one ended — a silently skipped result on every page.

So exactly `limit` rows are requested, and a cursor is returned whenever a page
comes back full. If the set happened to be an exact multiple of the page size,
the next page is **empty rather than absent**. An empty page is the end of the
set, not an error.

## Flags

The server states facts and leaves the reading to the caller. There is no
computed prose anywhere in a tool result: a sentence produced here would be
repeated downstream as an instance-backed finding, with the rule that generated
it nowhere in sight. Instead, a closed vocabulary of flags:

| Flag | Exact condition |
| --- | --- |
| `warninglisted` | the value matched at least one enabled warninglist |
| `warninglisted_and_to_ids` | the above, **and** at least one attribute carrying it has `to_ids=true` |
| `warninglist_coverage_partial` | `coverage` is `partial` |
| `warninglist_check_unavailable` | `coverage` is `unavailable` |
| `results_truncated` | a ceiling or the byte budget trimmed the result set |
| `warninglist_filtered_at_source` | `exclude_warninglisted` was set, so the instance pruned before this server saw anything |

## Configuration

Entirely by environment variable. Every value is validated at startup; an
unparseable one is a startup failure rather than a silent fallback, because
falling back to read-write or to a public listener is not a recoverable mistake.

| Variable | Role | Default |
| --- | --- | --- |
| `MISP_URL` | instance root — **required** | — |
| `MISP_KEY` | API key, sent as the `Authorization` header — **required** | — |
| `MISP_VERIFY_SSL` | verify the instance certificate | `true` |
| `MISP_TIMEOUT` | per-attempt timeout, `60s` or a bare number of seconds | `60s` |
| `MISP_READONLY` | `false` is what registers the write tools | `true` |
| `MISP_OUT_ROOT` | permitted root for `out_dir` | `$TMPDIR/mcp-misp` |
| `MISP_MAX_RESULTS` | lowers every result ceiling; never raises one | unset |
| `MISP_MAX_CONCURRENCY` | concurrent requests to the instance | `4` |
| `MISP_MAX_RETRIES` | retry attempts on 429/502/503/504 | `3` |
| `MISP_WARNINGLIST_LOCAL_FALLBACK` | allow the local engine | `true` |
| `MISP_WARNINGLIST_MAX_ENTRIES` | local index budget, in entries | `200000` |
| `MISP_WARNINGLIST_TTL` | local index lifetime | `6h` |
| `MISP_ALLOW_PUBLIC_BIND` | accept a non-loopback listen address | `false` |
| `MCP_TRANSPORT` | `stdio` or `http` | `stdio` |
| `MCP_HTTP_ADDR` | listen address (http transport) | `127.0.0.1:8080` |

Flags `-transport` and `-addr` override `MCP_TRANSPORT` and `MCP_HTTP_ADDR`.
`-version` prints the version on the first line, then the commit and the build
date, so `head -1` is a usable version string. The build date comes from the
tagged commit in UTC rather than from the build clock, so rerunning a release
produces the same binary.

### The API key

The key is never logged, never part of a struct that gets serialised, and never
present in an error message. Every error this server constructs passes through a
redaction step first — including errors whose text came back from the instance,
since a MISP that echoes the request into its error body is exactly the case a
header-only discipline misses. The transport error type deliberately has no
`Unwrap`, so nothing downstream can reach around the redacted copy.

### The loopback guard

`MCP_HTTP_ADDR` defaults to `127.0.0.1:8080`, and a non-loopback address —
including `:8080`, `0.0.0.0:8080` and `[::]:8080` — is refused at startup unless
`MISP_ALLOW_PUBLIC_BIND=true`.

This server has no authentication of its own and holds a MISP API key that may
be allowed to write. Anything able to reach the port holds that key.

**The container image is the documented exception.** A process bound to
127.0.0.1 inside a container is unreachable through a published port, so the
image sets `MCP_HTTP_ADDR=0.0.0.0:8080` and `MISP_ALLOW_PUBLIC_BIND=true`. The
loopback boundary moves to the host: publish the port as `127.0.0.1:8080:8080`
and put `tailscale serve` or a reverse proxy in front. The compose file in
`examples/` does this. Know that the guard is enforced by your port mapping, not
by the binary, when you run the image.

## Errors

Diagnoses are separated because they call for different work:

| Kind | Meaning |
| --- | --- |
| `refused_by_instance` | 401, 403 or another 4xx — permissions, or a malformed query |
| `not_found` | 404 |
| `rate_limited` | 429; retried with backoff, honouring `Retry-After` |
| `instance_error` | 5xx; only the gateway statuses are retried |
| `instance_timeout` | no answer in time — **not** retried, since replaying a slow query against a loaded instance multiplies the wait without changing the outcome |
| `instance_unreachable` | dial failure, reset, EOF |
| `tls_error` | certificate verification failed; points at `MISP_VERIFY_SSL` |
| `response_too_large` | the response exceeded the 64 MiB body cap; narrow the query |

Writes are never retried. A create that timed out mid-flight may well have
landed, and replaying it would duplicate the attribute.

## Install

### Container

```
docker pull ghcr.io/sebdraven/mcp-misp:latest
```

```
docker run --rm \
  -p 127.0.0.1:8080:8080 \
  -e MISP_URL=https://misp.example.org \
  -e MISP_KEY=your-api-key \
  ghcr.io/sebdraven/mcp-misp:latest
```

A compose service ready to paste, with the port bound to loopback, writes off
and the filesystem read-only:

```yaml
services:
  mcp-misp:
    image: ghcr.io/sebdraven/mcp-misp:latest
    pull_policy: always
    restart: unless-stopped
    environment:
      MISP_URL: ${MISP_URL:?set MISP_URL in .env}
      MISP_KEY: ${MISP_KEY:?set MISP_KEY in .env}
      MISP_VERIFY_SSL: ${MISP_VERIFY_SSL:-true}
      MISP_READONLY: ${MISP_READONLY:-true}
      MISP_OUT_ROOT: /var/lib/mcp-misp/out
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - misp-out:/var/lib/mcp-misp/out
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

volumes:
  misp-out:
```

Also in `examples/docker-compose.yml`, with `examples/env.example` alongside.

### Verifying the image signature

Release images are signed by digest with cosign, keyless, so the signature is
bound to the workflow that produced it rather than to a key someone holds. A
signature nobody knows how to verify is worth nothing, so:

```
cosign verify \
  --certificate-identity-regexp '^https://github\.com/sebdraven/mcp-misp/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/sebdraven/mcp-misp:v1.0.0
```

Verify a tag you pinned, not `latest`: a tag can move, and signing is done by
digest precisely because of that.

### Binaries

Each release carries `linux/amd64`, `linux/arm64` and `darwin/arm64` binaries
with their SHA-256 checksums.

### Claude Desktop (stdio)

```json
{
  "mcpServers": {
    "misp": {
      "command": "/usr/local/bin/mcp-misp",
      "args": ["-transport", "stdio"],
      "env": {
        "MISP_URL": "https://misp.example.org",
        "MISP_KEY": "replace-with-your-api-key",
        "MISP_READONLY": "true"
      }
    }
  }
}
```

Also in `examples/claude_desktop_config.json`; the HTTP form is in
`examples/mcp-http.json`.

## Known limits and reservations

Stated rather than hidden, because each one changes how a result should be read.

**`out_dir` confinement is TOCTOU by construction.** `out_dir` is resolved
against `MISP_OUT_ROOT` by following symlinks on the deepest existing ancestor,
and the write happens afterwards. Between those two moments, anyone with write
access to `MISP_OUT_ROOT` can substitute a symlink. The confinement therefore
assumes the root is **not shared with an untrusted third party while the server
is running**. Point `MISP_OUT_ROOT` at a directory owned by the account running
this server.

**Galaxy expansion under `metadata=1` is unverified.** Events are read with
`POST /events/restSearch` and `metadata=1`, which MISP documents as returning
the event, its tags and its relations while omitting attributes. Whether the
galaxy expansion survives that depends on the MISP version, and it has **not
been verified against a live instance**. When `galaxies` is requested and none
come back, the tool says so in a note rather than implying the event has none —
but the test covering this pins the *message*, not the instance's actual
behaviour. This reservation is to be settled against a real instance. **If
`metadata=1` turns out not to expand galaxies on current MISP versions, that
note becomes permanent noise on every call and the field should be dropped from
the vocabulary instead.**

**`exclude_warninglisted` destroys the count.** It asks the instance to remove
warninglisted attributes before sending them, and MISP does not report how many
it removed. The number of rows that come back is therefore **not a measure of
how often the value appears on this instance**. Results carrying the
`warninglist_filtered_at_source` flag must not be used for prevalence. Leave the
option off and read the per-row verdicts instead.

**The last page can be empty.** See above — a consequence of MISP's
`page` × `limit` pagination, and the alternative would silently skip a record
per page.

**Attribute-level and event-level tags cannot always be told apart.** MISP marks
tags inherited from the parent event with an `inherited` field. Instances too
old to send it return both kinds indistinguishably; in that case everything is
reported as attribute-level rather than guessed at, since guessing would
misattribute an event's TLP tag to a single attribute.

**Objects are not modelled.** `misp_event` never fetches the event object graph.
Object membership is visible through the `object_id` and `object_relation`
attribute fields, and nothing reconstructs an object's semantics.

**Object relationship types are written unchecked on most instances.** See the
section above. The consequence to carry: a misspelt relationship type is
accepted by MISP and produces two relations that look alike and never match.
Read `unvalidated_relationship_types` before considering a batch done.

**The structured-value detector is a heuristic, and it produces false
positives.** `allow_unknown_relations` refuses coercion for anything shaped like
a hash, an IP, a CIDR, a domain, a URL or an email. Shape is all it has to go
on, so a filename that happens to be 64 hex characters reads as a SHA-256, a
version string reads as a hostname, and a template's own `sane_default` can trip
it. Those refusals are wrong, and there is no override for them.

That asymmetry is deliberate: a refusal is recoverable in one move, whereas an
IOC written as `text` is in the database and invisible to every pivot, with
nothing to signal it. So the refusal is built to be actionable rather than
merely negative — it names the relation to use instead:

> value looks like sha256 and would be written as free text, which MISP never
> correlates on; allow_unknown_relations does not cover this — use relation
> "sha256", which template "file" declares as sha256

**Where that advice runs out**: when the template declares no relation of the
detected type at all, the message can only name the attribute types that would
have fitted. There is then no way to place the value on that object, and the
value belongs somewhere else — on its own object of a fitting template, linked
by a reference, or as a plain attribute through `misp_add_attribute`.

**The object-template cache can validate against a stale definition.** Template
definitions are cached for an hour, and templates carry a version. If
misp-objects is updated on the instance inside that window — a new relation, a
changed type, a tightened `required` — validation runs against the definition
this server fetched before the update. The consequence is a batch refused for a
relation that now exists, or accepted against a constraint that has since
changed. The version this server used is reported by `misp_object_templates`;
restarting the server clears the cache.

**Write ceilings are independent of `MISP_MAX_RESULTS`.** That variable bounds
how much comes back; how much one call may push into somebody's instance is a
different question, and is bounded by the batch ceilings reported by
`misp_describe_instance`.

**The organisation index is cached for an hour.** An organisation created during
that window resolves to an empty name until the cache expires.

## CI/CD

GitHub Actions, all actions pinned to a commit hash, `permissions: contents:
read` by default with anything more elevated per job.

- **`ci.yml`** — `gofmt`, `go vet`, `go test -race` (no network: every test runs
  against an httptest stub, so CI never becomes a client hitting somebody's
  instance), `staticcheck`, `zizmor`, a build with a `-version` smoke test, a
  startup check that a missing `MISP_URL` is fatal, a Docker build and an image
  smoke test. On a push to main and only then, a multi-arch `edge` image is
  published to GHCR — never on `pull_request`, so a fork PR cannot write to the
  registry.
- **`release.yml`** — tags only. The tag format is validated before anything is
  published (`v*` also matches `vfoo`). Version, commit and build date are
  injected with `-ldflags`, the build date coming from the commit rather than
  the wall clock so a rerun produces the same binary. Binaries publish first,
  then the multi-arch image with provenance and SBOM, signed by digest with
  cosign. Image tags: `vX.Y.Z`, `vX.Y`, `vX`, the commit sha, and `latest` —
  which a prerelease tag never moves. A prerelease tag produces a GitHub release
  marked as such.
- **`zizmor`** runs on push and pull request, blocking, with no
  `continue-on-error`. It audits every workflow in the repository, `ci.yml` and
  `release.yml` included, which is what checks the SHA pinning,
  `persist-credentials: false` and minimal permissions — none of that is
  duplicated by hand. Findings are uploaded as SARIF to code scanning.
  Exceptions live in `.github/zizmor.yml`, versioned and each carrying its
  reason; there are no inline ignores.

Everything is verified in CI. There is no local build, lint or test step in this
document on purpose.

## Licence

MIT. See `LICENSE.md`.
