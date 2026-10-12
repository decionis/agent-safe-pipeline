"""Build the two banking briefs with editable text and vector flow diagrams.

Requires reportlab; use --font-dir for a directory containing NotoSans*.ttf.
No network access, template service, or generated logo is involved.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Preformatted


ROOT = Path(__file__).resolve().parents[2]
WIDTH, HEIGHT = A4
MARGIN = 42
CONTENT = WIDTH - 2 * MARGIN
NAVY = "#0A192F"
PURPLE = "#7C3AED"
BLUE = "#1E3A8A"
INK = "#17263F"
MUTED = "#516078"
LINE = "#DCE2ED"
PALE = "#F5F1FE"
GREY = "#F5F7FB"
WHITE = "#FFFFFF"
GREEN = "#13795B"
RED = "#B4233A"
AMBER = "#946200"
DATE = "12 October 2026"
LOGO = ROOT / "docs/banking/assets/Decionis.png"


def color(value):
    return colors.HexColor(value)


class Brief:
    """Top-origin page coordinates with bounds checks on every text block."""

    def __init__(self, path, title, short, pages, date=DATE):
        self.path = path
        self.short = short
        self.pages = pages
        self.date = date
        self.page = 0
        self.boxes = []
        self.c = canvas.Canvas(str(path), pagesize=A4, pageCompression=1)
        self.c.setTitle(title)
        self.c.setAuthor("Decionis, Inc.")
        self.c.setSubject("Bank execution authority and joint card authorization with Koard")

    def rect(self, x, y, w, h, fill=WHITE, stroke=None, radius=7):
        self.c.setFillColor(color(fill))
        self.c.setStrokeColor(color(stroke or fill))
        self.c.setLineWidth(0.7)
        self.c.roundRect(x, HEIGHT - y - h, w, h, radius, fill=1, stroke=int(stroke is not None))

    def text(self, x, y, w, value, size=10.1, shade=INK, bold=False, leading=None, center=False):
        style = ParagraphStyle(
            "block", fontName="DecionisBold" if bold else "Decionis",
            fontSize=size, leading=leading or size * 1.38, textColor=color(shade),
            alignment=TA_CENTER if center else TA_LEFT, spaceBefore=0, spaceAfter=0,
            splitLongWords=True,
        )
        p = Paragraph(value, style)
        _, h = p.wrap(w, HEIGHT)
        if x < MARGIN - 1 or x + w > WIDTH - MARGIN + 1 or y < 20 or y + h > HEIGHT - 47:
            raise ValueError(f"Text outside page {self.page}: {value[:100]} at {x,y,w,h}")
        p.drawOn(self.c, x, HEIGHT - y - h)
        self.boxes.append({"page": self.page, "x": x, "y": y, "w": w, "h": h, "text": value})
        return h

    def line(self, x1, y1, x2, y2, shade=LINE, width=1, dashed=False):
        self.c.saveState()
        self.c.setStrokeColor(color(shade))
        self.c.setLineWidth(width)
        if dashed:
            self.c.setDash(2, 3)
        self.c.line(x1, HEIGHT - y1, x2, HEIGHT - y2)
        self.c.restoreState()

    def arrow(self, x1, y1, x2, y2, shade=PURPLE):
        self.line(x1, y1, x2, y2, shade, 1.2)
        import math
        angle = math.atan2(y2 - y1, x2 - x1)
        for delta in (-0.55, 0.55):
            self.line(x2, y2, x2 - 5 * math.cos(angle + delta), y2 - 5 * math.sin(angle + delta), shade, 1.2)

    def begin(self, section, title, intro=None, cover=False):
        if self.page:
            self.c.showPage()
        self.page += 1
        self.c.setFillColor(color(PURPLE))
        self.c.rect(0, HEIGHT - 5, WIDTH, 5, stroke=0, fill=1)
        self.c.drawImage(str(LOGO), MARGIN, HEIGHT - 68, width=153, height=45.1, mask="auto", preserveAspectRatio=True)
        self.text(WIDTH - MARGIN - 205, 35, 205, self.short.upper(), size=7.2, shade=MUTED)
        self.line(MARGIN, 83, WIDTH - MARGIN, 83)
        self.text(MARGIN, 100, CONTENT, section.upper(), 8, PURPLE, True)
        title_y = 125
        h = self.text(MARGIN, title_y, CONTENT, title, 32 if cover else 25, NAVY, True, leading=37 if cover else 30)
        if intro:
            self.text(MARGIN, title_y + h + 13, CONTENT, intro, 11 if cover else 10.3, MUTED)
        self.line(MARGIN, HEIGHT - 37, WIDTH - MARGIN, HEIGHT - 37)
        self.c.setFont("Decionis", 7.1)
        self.c.setFillColor(color(MUTED))
        self.c.drawString(MARGIN, 23, "Decionis, Inc.  |  " + self.date)
        self.c.drawRightString(WIDTH - MARGIN, 23, f"{self.page:02d} / {self.pages:02d}")

    def label(self, y, text):
        self.text(MARGIN, y, CONTENT, text, 12, NAVY, True)

    def measure(self, w, value, size, bold=False, leading=None):
        style = ParagraphStyle(
            "measure", fontName="DecionisBold" if bold else "Decionis",
            fontSize=size, leading=leading or size * 1.38, splitLongWords=True,
        )
        _, h = Paragraph(value, style).wrap(w, HEIGHT)
        return h

    def note(self, y, title, body, h=None, fill=PALE):
        """A tinted callout; with no height given it is sized to its body. Returns the height used."""
        if h is None:
            h = self.measure(CONTENT - 26, body, 9.25) + 41
        self.rect(MARGIN, y, CONTENT, h, fill)
        self.text(MARGIN + 13, y + 10, CONTENT - 26, title, 10.2, PURPLE, True)
        used = self.text(MARGIN + 13, y + 29, CONTENT - 26, body, 9.25)
        if used + 39 > h:
            raise ValueError(f"Note overflows on page {self.page}: {title}")
        return h

    def box(self, x, y, w, h, title, body="", accent=PURPLE, fill=WHITE):
        self.rect(x, y, w, h, fill, LINE)
        self.c.setFillColor(color(accent))
        self.c.rect(x, HEIGHT - y - h, 3, h, fill=1, stroke=0)
        th = self.text(x + 11, y + 10, w - 22, title, 10.1, accent, True)
        if body:
            bh = self.text(x + 11, y + 17 + th, w - 22, body, 9.1, INK)
            if 27 + th + bh > h:
                raise ValueError(f"Box overflows page {self.page}: {title}")

    def table(self, y, widths, heads, rows, size=9.2):
        x = MARGIN
        header_h = 30
        self.rect(x, y, CONTENT, header_h, NAVY, radius=0)
        for w, value in zip(widths, heads):
            self.text(x + 9, y + 8, w - 18, value, 8.6, WHITE, True)
            x += w
        y += header_h
        for index, row in enumerate(rows):
            paras = []
            for w, value in zip(widths, row):
                style = ParagraphStyle("cell", fontName="Decionis", fontSize=size, leading=size * 1.35)
                p = Paragraph(value, style)
                _, h = p.wrap(w - 18, HEIGHT)
                paras.append(h)
            row_h = max(paras) + 20
            self.rect(MARGIN, y, CONTENT, row_h, GREY if index % 2 == 0 else WHITE, radius=0)
            x = MARGIN
            for w, value in zip(widths, row):
                self.text(x + 9, y + 9, w - 18, value, size)
                x += w
            self.line(MARGIN, y + row_h, WIDTH - MARGIN, y + row_h)
            y += row_h
        return y

    def sequence(self, y, lanes, events, bank_lanes=(), row_height=38):
        gap = 8
        lane_w = (CONTENT - gap * (len(lanes) - 1)) / len(lanes)
        centers = [MARGIN + i * (lane_w + gap) + lane_w / 2 for i in range(len(lanes))]
        end = y + 48 + row_height * len(events)
        for i, name in enumerate(lanes):
            x = centers[i] - lane_w / 2
            if i in bank_lanes:
                self.rect(x - 2, y - 5, lane_w + 4, end - y + 6, GREY)
            self.rect(x, y, lane_w, 37, PALE if i not in bank_lanes else NAVY)
            self.text(x + 6, y + 9, lane_w - 12, name, 8.4, WHITE if i in bank_lanes else PURPLE, True, center=True)
            self.line(centers[i], y + 42, centers[i], end, LINE, dashed=True)
        for index, (source, target, label) in enumerate(events):
            row = y + 53 + row_height * index
            if source == target:
                x = centers[source] - lane_w / 2 + 2
                self.rect(x, row - 4, lane_w - 4, 29, PALE)
                self.text(x + 4, row, lane_w - 12, label, 8, PURPLE, True, center=True)
            else:
                a, b = centers[source], centers[target]
                left = min(a, b)
                w = max(abs(a - b), lane_w)
                self.rect(left - 3, row - 3, w + 6, 17, WHITE, radius=0)
                self.text(left, row - 1, w, label, 8.3, INK, center=True, leading=10)
                self.arrow(a, row + 18, b, row + 18, PURPLE if target in bank_lanes else BLUE)
        return end

    def code(self, y, value, h):
        self.rect(MARGIN, y, CONTENT, h, GREY)
        p = Preformatted(value, ParagraphStyle("code", fontName="DecionisMono", fontSize=8.7, leading=13))
        w, used = p.wrap(CONTENT - 26, h - 20)
        if w > CONTENT - 26 or used > h - 20:
            raise ValueError("Code block overflow")
        p.drawOn(self.c, MARGIN + 13, HEIGHT - y - 11 - used)

    def save(self):
        if self.page != self.pages:
            raise ValueError("Unexpected page count")
        self.c.save()
        return {"file": self.path.name, "pages": self.page, "text_blocks": len(self.boxes)}


def bank_gateway_deployment(d):
    d.begin("Gateway placement", "Put agent calls through AgentSafe", "Route each tool's consequential HTTP calls through the gateway before they reach the system that performs the action.")
    cw = (CONTENT - 36) / 3
    for i, (title, body) in enumerate([
        ("Agent tool client", "Uses the gateway as its API base URL. Keeps the operation's stable idempotency key."),
        ("AgentSafe gateway", "Captures intent; asks Decionis; verifies and claims the grant before dispatch."),
        ("Bank API", "Receives the admitted request and performs the action. Enforces its own idempotency."),
    ]):
        x = MARGIN + i * (cw + 18)
        d.box(x, 230, cw, 106, title, body, BLUE if i != 1 else PURPLE)
        if i < 2:
            d.arrow(x + cw + 1, 281, x + cw + 17, 281)
    d.note(355, "Make the gateway the only permitted route", "A base URL change is routing. Restrict direct API access from the agent using network or provider controls, and test that bypass fails. Protect the gateway's HTTP listener with the bank's TLS ingress or mesh.", h=81)
    d.label(456, "The tool changes its address; the gateway keeps the upstream")
    d.code(480, "Before: POST https://payments.bank.example/payments\nAfter:  POST https://agentsafe.bank.example/payments\nUpstream on gateway: https://payments.bank.example", 66)
    d.text(MARGIN, 562, CONTENT, "Keep the method, relative path, query, body and upstream authentication. Configure one gateway per upstream; a base path is added only once. This is a reverse proxy, not a generic HTTP_PROXY / CONNECT endpoint. Changing the model endpoint alone does not govern separate tool calls.", 9.5)
    d.label(644, "Choose the integration surface")
    d.text(MARGIN, 668, CONTENT, "<b>Addressed gateway:</b> configure the tool or SDK base URL and govern POST, PUT, PATCH and DELETE. GET, HEAD and OPTIONS must remain safe at the API.<br/><br/><b>Transparent interception:</b> use the supported sidecar when URLs cannot change; governing HTTPS requires the workload to trust the interception CA. Observation alone is not enforcement.<br/><br/><b>Trusted executor:</b> use explicit action APIs for bank-owned credentials, proposer/operator separation and the Koard card flow.", 9.2)

    d.begin("On-premises setup", "Deploy inside the bank", "The gateway and the decision service can be placed independently. A bank-operated gateway can enforce using the hosted Decionis authority.")
    d.note(226, "Keep the relay in the bank; choose the policy data deliberately", "Agent to gateway to bank API stays on the bank's network. Intent, query, context and embedded JSON fields go to the configured authority. Turning body embedding off does not redact the other fields.", h=81)
    y = 331
    for number, title, body in [
        ("01", "Choose the host or cluster", "Pin the approved image digest. Run the gateway in Docker on a bank host, or use the gateway Helm chart beside the protected Service. Put TLS in front of the listener."),
        ("02", "Mount the authority credential", "Set the workspace organization and HTTPS authority endpoint. Production reads the key from a secret file, not a key value in environment variables. Keep it separate from agent credentials."),
        ("03", "Configure the upstream and named routes", "Point the tool at the gateway; keep the bank API as upstream. Start in shadow with unmatched writes governed. Restrict both ingress and bypass, and allow the required authority egress."),
        ("04", "Start, observe and verify", "Run agentsafe proxy --config agentsafe.yaml, or install the chart. Check health, then test actual decisions and effects. Retain per-replica evidence and plan routing for held approvals."),
    ]:
        d.rect(MARGIN, y, 30, 30, PALE)
        d.text(MARGIN + 5, y + 7, 20, number, 10, PURPLE, True, center=True)
        d.text(MARGIN + 43, y, CONTENT - 43, title, 10.3, NAVY, True)
        h = d.text(MARGIN + 43, y + 19, CONTENT - 43, body, 9.1)
        y += max(65, h + 31)
    d.code(y + 9, "# Runtime YAML: agentsafe.yaml\nauthority:\n  mode: shadow\n  failurePolicy: failClosed\ninterception:\n  unmatched: govern", 100)
    d.text(MARGIN, y + 126, CONTENT, "<b>Promote after validation.</b> Runtime YAML uses authority.mode: enforcement; Helm uses gateway.mode: enforcement. Keep fail closed. A bank-run authority is the self-managed tier on page 7; the local demo is not a production authority.", 9.1)

    d.begin("Managed cloud setup", "Connect to the hosted gateway", "The assigned tenant endpoint is a separate deployment option from running the gateway inside the bank and using a hosted authority.")
    d.note(225, "Current managed gateway: shadow only", "The hosted runtime refuses enforcement mode. Admitted requests can create real effects at the API while Decionis observes policy. For enforcement, run a bank-operated gateway with the configured authority.", h=81)
    y = 329
    for number, title, body in [
        ("01", "Obtain the assigned endpoint and keys", "Decionis onboards the tenant and supplies its URL, ingress key, origin-proof token, limits and report access. Confirm region and retention. There is no self-serve setup assumed here."),
        ("02", "Check the API is compatible", "Use a public HTTPS origin with valid TLS. The relay cannot present an upstream client certificate, reach private APIs, stream responses or upgrade WebSockets."),
        ("03", "Prove control of the origin", "Serve the issued token at /.well-known/agentsafe-upstream without authentication or redirects. Keep it published and wait for the proof check before sending business traffic."),
        ("04", "Change the tool base URL", "Use the assigned tenant host and add AgentSafe-Tenant-Key from the application's secret store. Keep the API credential separate. The cloud gateway processes the full relayed request."),
        ("05", "Send an approved test operation", "Check the passthrough response and shadow observation. A would-be BLOCK still reaches the API. Use the operator's report access; a tenant key does not open status or metrics."),
    ]:
        d.rect(MARGIN, y, 27, 27, PALE)
        d.text(MARGIN + 4, y + 6, 19, number, 9.7, PURPLE, True, center=True)
        d.text(MARGIN + 39, y, CONTENT - 39, title, 10, NAVY, True)
        h = d.text(MARGIN + 39, y + 18, CONTENT - 39, body, 8.95)
        y += max(60, h + 29)
    d.code(y + 9, "POST https://TENANT_ID.decionisedge.com/payments\nAgentSafe-Tenant-Key: ISSUED_INGRESS_KEY\nAuthorization: Bearer UPSTREAM_API_CREDENTIAL\n\nExpected: agentsafe-mode: SHADOW\n          agentsafe-execution: PASSTHROUGH", 99)
    d.text(MARGIN, y + 120, CONTENT, "Complete configuration, Docker and Helm commands, origin-proof details and acceptance checks: docs/gateway/deployment.md in the accompanying repository.", 8.4, MUTED)


def bank_brief(out):
    d = Brief(out / "AgentSafe-for-banks.pdf", "AgentSafe for banks", "Bank architecture brief", 9)
    d.begin("Execution authority", "AgentSafe<br/>for banks", "An independent authorization check between an AI agent's proposal and the action your bank executes.", cover=True)
    d.label(269, "The bank-operated deployment")
    d.rect(MARGIN, 296, 307, 284, GREY, LINE)
    d.rect(365, 296, CONTENT - 323, 284, PALE, LINE)
    d.text(54, 308, 279, "INSIDE YOUR BANK", 8.2, NAVY, True)
    d.text(377, 308, 162, "DECISION AUTHORITY", 8.2, PURPLE, True)
    d.box(57, 338, 132, 65, "AI agent", "Proposes an action", BLUE)
    d.box(205, 338, 128, 65, "Secret store", "Bank credentials", BLUE)
    d.box(57, 432, 276, 67, "AgentSafe", "Captures intent, enforces the decision, claims the grant and dispatches the action.")
    d.box(57, 526, 132, 43, "Bank systems", accent=BLUE)
    d.box(205, 526, 128, 43, "Bank evidence", accent=BLUE)
    d.box(379, 398, 160, 127, "Decionis", "Evaluates bank policy.<br/><br/>Returns ALLOW, ESCALATE or BLOCK; issues bound grants and decision evidence.")
    d.arrow(122, 403, 122, 432)
    d.arrow(267, 403, 267, 432)
    d.arrow(122, 499, 122, 526)
    d.arrow(267, 499, 267, 526)
    d.arrow(333, 450, 379, 450)
    d.arrow(379, 481, 333, 481)
    d.text(MARGIN, 590, CONTENT, "Intent and lifecycle calls cross the boundary over authenticated HTTPS. For cards, the bank's issuer hook asks AgentSafe to match a previously held grant, or to evaluate an authorization that has no hold at the commit boundary; the issuer executes the authorization.", 9.4, MUTED)
    gap = 12
    cw = (CONTENT - 2 * gap) / 3
    for i, (title, body, shade) in enumerate([
        ("ALLOW", "Execute only after the exact grant is verified and claimed.", GREEN),
        ("ESCALATE / HOLD", "Wait before the action. Approval is evidence for a new decision.", AMBER),
        ("BLOCK", "The governed action does not reach the bank system.", RED),
    ]):
        d.box(MARGIN + i * (cw + gap), 653, cw, 110, title, body, shade)

    d.begin("Data and control", "A deliberate data boundary", "This table describes data sent to the decision service. The managed cloud gateway also processes the full relayed request; see the deployment options on pages 4-6.")
    y = d.table(227, [126, 173, CONTENT - 299], ["DATA", "TRUSTED EXECUTOR", "HTTP GATEWAY"], [
        ("Bank credentials", "Resolved inside the bank for registered handlers.", "Client headers can be relayed upstream; their raw values are not included in the policy request."),
        ("Intent and context", "Declared action, target, parameters and signals go to the authority.", "Method, path, query and configured identity/context go to the authority."),
        ("Request body", "An adapter controls the declared parameters. Those parameters may contain business data.", "Small JSON bodies are embedded by default (up to 64 KiB). Set maxEmbeddedBodyBytes to 0 to disable embedding."),
        ("Response and result", "Built-in handlers return bounded result/effect evidence. Review custom adapters' output.", "The upstream response is relayed to the caller; it is not sent as the policy request."),
        ("Card data", "Use opaque issuer token references. The cards profile refuses PAN-shaped card references.", "A generic proxy does not automatically sanitize PANs or sensitive fields in bodies and URLs."),
    ], size=8.9)
    d.note(y + 17, "A digest binds data; it does not remove data", "Body embedding can be disabled while the raw bytes remain hash-bound. Path, query, intent parameters and signals still need the bank's data classification review.", h=77)
    y += 111
    d.label(y, "Policy and failure remain explicit")
    d.text(MARGIN, y + 23, CONTENT, "The bank owns policy and its approver roles. Enforcement defaults to fail closed when authority is unavailable. The gateway also supports an explicit fail-open configuration, which forwards ungoverned traffic; exclude it from a strict bank enforcement profile. Shadow mode observes policy while forwarding traffic, subject to transport and admission guards.", 9.6)

    d.begin("Joint card delivery", "Koard + Decionis", "Koard is the design partner for cardholder-present verification before an agentic card transaction. Together, the flow links presence to a precise purchase and a bank-controlled authorization boundary.")
    y = d.table(240, [96, CONTENT - 96], ["OWNER", "RESPONSIBILITY"], [
        ("Koard", "Prove cardholder presence for the intended card and sign evidence bound to the purchase intent."),
        ("Decionis", "Verify admitted evidence, apply bank policy and issue a short-lived, single-use execution grant."),
        ("AgentSafe", "Hold the grant in the bank; match the issuer's authorization request and claim the grant once."),
        ("Issuer", "Own final approve/decline, account and fraud controls, the processor integration and the outcome report."),
    ], size=9.5)
    start = y + 27
    cw = (CONTENT - 24) / 3
    for i, (title, body) in enumerate([
        ("01  Before card use", "Capture purchase intent. Complete Koard verification for the cardholder-present flow. Re-evaluate; hold the grant on ALLOW."),
        ("02  At authorization", "Match token, merchant, currency and amount ceiling; claim once. Answer APPROVE or NO_MATCH. With no hold, policy can answer PENDING for the cardholder's tap in the fraud queue."),
        ("03  After the result", "The issuer reports approved or declined. AgentSafe compares the observed effect and submits finalization evidence."),
    ]):
        d.box(MARGIN + i * (cw + 12), start, cw, 165, title, body)
        if i < 2:
            d.arrow(MARGIN + i * (cw + 12) + cw + 1, start + 75, MARGIN + (i + 1) * (cw + 12) - 1, start + 75)
    d.note(start + 183, "Presence, execution authority and issuer approval are separate", "A Koard proof is evidence, not permission. AgentSafe's APPROVE means a matching grant was claimed. The issuer still makes the card-network decision. NO_MATCH requires an explicit bank policy response.", h=83)

    bank_gateway_deployment(d)

    d.begin("Hosting tiers", "Where the authority runs", "Three ways to run the authority that mints grants, written once so a security review reads the same answer here, in the deployment guide (docs/gateway/deployment.md) and at decionis.com/docs/card-authorization. In every tier the gateway, its hold store, its evidence chains and the ISO 8583 interceptor run inside the bank.")
    y = d.table(240, [118, 196, CONTENT - 314], ["TIER", "WHO MINTS THE GRANTS", "PRESENCE AND ARRANGEMENT"], [
        ("Hosted", "Decionis, multi-tenant, at api.decionis.com in one Azure region: Central US today, regional residency planned.", "The Decionis Presence service for bank-role escalations; a cardholder's tap never goes through it. Arranged by onboarding: a workspace, its organisation id and a service key. The default."),
        ("Dedicated single-tenant", "Decionis, in a deployment for one bank: its own database and Key Vault, so its own signing keys, in an agreed region.", "Presence as hosted. An explicitly agreed deployment; it does not exist for a bank until agreed, and nothing here assumes it."),
        ("Self-managed, commercial licence", "The bank, from the versioned Helm chart, in its own cluster with its own Postgres, egress-only or air-gapped. Decisions, dossiers and policy stay inside.", "Presence connected by service token and pinned keys; no self-managed Presence is offered, and a bank whose escalations go only to the cardholder's tap needs none. The edge evaluator module comes with the licence when latency puts the claim at the edge."),
    ], size=8.8)
    y += 14 + d.note(y + 14, "What never leaves the bank, in any tier", "The hold store, the evidence chains, the card hold key, the ISO 8583 tokenizer key, the bank's credentials and the card number stay inside the bank. Only the managed gateway on page 6 is Decionis-run, and it is shadow only.") + 16
    d.label(y, "Which tier a bank needs")
    d.text(MARGIN, y + 23, CONTENT, "Hosted is the default, and the shadow weeks run there. Dedicated single-tenant is for a bank that requires its own signing keys and region without running the service. Self-managed is for a bank whose decisions, dossiers and policy may not leave it, and brings the edge evaluator for a local claim.", 9.6)
    d.text(MARGIN, y + 82, CONTENT, "<b>Assurance profile as supplied in October 2026.</b> Azure Central US; default dossier retention of 365 days, configurable, with deletion on request. SOC 2 and an independent assessment were not yet completed. Confirm the current region, retention, licensing and assurance evidence during bank diligence.", 8.5, MUTED)

    d.begin("Key custody", "Where every signing key lives", "Whose custody each key is in, by tier. Decionis signs grants, dossiers and policy bundles with Ed25519; the bank's own keys never reach Decionis. Variable names and rotation runbooks are in the deployment guide.")
    y = d.table(227, [150, 120, 120, CONTENT - 390], ["KEY", "HOSTED", "DEDICATED SINGLE-TENANT", "SELF-MANAGED"], [
        ("The execution grant key, the decision dossier key and the evidence pack key (Ed25519; a previous grant key during a rotation)", "Key Vault secrets of the Decionis deployment, purge-protected: one active grant key per deployment, not one per tenant", "The bank's own Key Vault in its deployment: one key per bank", "The bank's secret manager, supplied to the chart as the API Secret"),
        ("The policy bundle signing key; the edge evaluator pins its public JWKS", "A Decionis Key Vault secret, rotated with overlap under its runbook", "Decionis's, as hosted: Decionis signs bundles for every tier", "Decionis's; the bank pins the public JWKS and verifies offline"),
        ("The Presence Record keys", "The Presence service's own; the authority pins their thumbprints", "As hosted", "As hosted; the thumbprints are pinned in the bank's API Secret"),
        ("A presence provider's keys: Koard's JWKS, or a key the bank registers itself", "The provider's own; Decionis holds public keys only, in the directory and the bank's admissions", "As hosted", "As hosted, in the bank's authority"),
        ("The bank's workspace key and, in DIRECT escalation, its Presence key", "The bank's secret store, mounted as files; production refuses values in environment variables", "As hosted", "As hosted"),
        ("The gateway's own keys: TLS, evidence signing, usage reports, the card hold key, the ISO 8583 tokenizer key, store connection strings, downstream and principal credentials", "The bank's secret store, never Decionis's: read at the moment of use and printed nowhere; the card number never leaves the bank's process", "As hosted", "As hosted"),
    ], size=8.3)
    d.note(y + 14, "The HSM-backed option", "Key Vault's HSM-backed keys and Managed HSM do not hold Ed25519, so the grant, dossier and bundle keys are software keys kept as Key Vault secrets, purge-protected and rotated with an overlap. A dedicated or self-managed deployment that requires HSM custody of the grant key gets a change of key type, made per deployment on request and verified end to end before enforcement; it is not a switch.")

    d.begin("Deployment and acceptance", "Start with one bank workflow", "Make the scope, data boundary, failure policy and evidence requirements reviewable before enabling enforcement. AgentSafe is Apache-2.0 source; a dedicated or self-managed authority is a commercial arrangement, as on page 7.")
    y = 227
    for number, title, body in [
        ("01", "Choose the action and integration", "Use the gateway for governed HTTP calls or the trusted executor for explicit actions and bank adapters. Card matching is an executor API; the ISO 8583 interceptor puts it on the wire."),
        ("02", "Configure identity, secrets and egress", "Separate proposer, issuer-app and issuer-hook principals. Keep privileged credentials at the execution boundary, restrict bypass paths, allow only the authority, secret-store and bank endpoints."),
        ("03", "Observe and tune policy", "Run a controlled shadow workflow. Review decisions, submitted data and missing signals with risk and operations. Shadow observations do not create card execution grants."),
        ("04", "Enforce and exercise failures", "Verify ALLOW and claim, BLOCK, ESCALATE, PENDING, expiry, replay, restart and timeout. Measure the hook's full latency, including the claim, against its deadline and its placement's budget."),
        ("05", "Roll out with operational ownership", "Enable one issuing range at a time. Route SIEM evidence, monitor open attempts, rehearse the stop and key revocation, and document the issuer's NO_MATCH policy."),
    ]:
        d.rect(MARGIN, y, 30, 30, PALE)
        d.text(MARGIN + 5, y + 7, 20, number, 10, PURPLE, True, center=True)
        d.text(MARGIN + 43, y, CONTENT - 43, title, 10.4, NAVY, True)
        h = d.text(MARGIN + 43, y + 20, CONTENT - 43, body, 9.4)
        y += max(68, h + 34)
    h = d.note(y + 6, "Replicas, restarts and latency", "Holds are keyed by card and merchant. One replica keeps them in process; several replicas, or holds that must survive a restart, share a Postgres hold store (EXECUTOR_CARD_HOLDS_STORE=postgres) whose rows are sealed under a key in the bank's secret store, so the hook and its result may reach any replica. Hook answer budgets at the 99th percentile: 150 ms with the hosted authority in the same cloud region, 300 ms across regions, 10 ms with a local claim at the edge; the in-process match is under a millisecond.")
    d.note(y + 18 + h, "Enforcement on one range, with a stop", "The ISO 8583 interceptor governs only the issuing ranges named in its binRanges; everything else passes to the host untouched and is recorded as ungoverned. POST /v1/control/halt by an operator holding halt, or the halt file on the host, stops new work: the hook answers NO_MATCH with EXECUTOR_HALTED, and the interceptor's fail policy says whether a frame is then forwarded or declined.")
    return d.save()


def joint_brief(out):
    d = Brief(out / "Koard-and-Decionis-agentic-authorization-design-flow.pdf", "Koard and Decionis: agentic card authorization", "Koard + Decionis | Joint design", 7)
    d.begin("Joint delivery architecture", "Koard + Decionis<br/>Agentic card authorization", "Cardholder-present verification before card use, bound to a purchase intent and enforced at the bank's authorization boundary.", cover=True)
    d.note(271, "The joint delivery", "Koard is the design partner for cardholder-present verification. Decionis provides independent execution authority. AgentSafe enforces the grant boundary in the bank; the issuer retains the final card decision.", h=82)
    y = d.table(374, [103, 202, CONTENT - 305], ["PARTICIPANT", "OWNS", "OUTPUT"], [
        ("Agent platform", "Propose the precise purchase; wait before presenting the card.", "Purchase intent"),
        ("Koard", "Verify cardholder presence and bind the intended card to the purchase.", "Signed presence evidence"),
        ("Decionis", "Verify evidence and apply the bank's versioned policy.", "Decision and bound grant"),
        ("AgentSafe", "Capture, hold, match, claim once and record effect evidence.", "APPROVE / PENDING / NO_MATCH"),
        ("Issuer / processor", "Operate the hook and account/fraud controls; authorize or decline.", "Card decision and result"),
    ], size=9.2)
    d.label(y + 23, "Three phases, with one clear point of execution")
    d.text(MARGIN, y + 46, CONTENT, "<b>Before card use:</b> establish intent and required presence, then obtain authority.<br/><b>At authorization:</b> match and claim within the issuer's measured deadline.<br/><b>Afterward:</b> record what the issuer actually did and reconcile uncertainty.", 10)
    d.text(MARGIN, y + 110, CONTENT, "A tap is awaited before card submission or, when the platform can pend, in the bank's fraud queue. The match itself never waits for a tap.", 9.8, PURPLE, True)

    d.begin("Phase 1 | Before card use", "Verify presence, then decide", "The original purchase stays immutable. Koard supplies evidence for that purchase; only a fresh policy decision can issue an executable grant.")
    end = d.sequence(231, ["Agent / issuer app", "AgentSafe", "Decionis", "Koard"], [
        (0, 1, "1. Submit purchase intent"),
        (1, 2, "2. Evaluate bound intent"),
        (2, 1, "3. ESCALATE: hold purchase"),
        (2, 3, "4. Notify issuer's Koard flow"),
        (3, 0, "5. Cardholder check + signed Koard proof"),
        (0, 1, "6. Resume with Koard proof"),
        (1, 2, "7. Verify proof; re-evaluate"),
        (2, 1, "8. ALLOW + bound grant"),
        (1, 0, "9. HELD_FOR_AUTHORIZATION"),
    ], bank_lanes=(1,), row_height=38)
    d.text(MARGIN, end + 14, CONTENT, "Koard signs the verification result and returns it through the agreed issuer-app integration. The issuer app's backend presents it as an operator holding escalations.resume, or the agent that proposed presents it; either way the authority re-evaluates the same intent. A bank-role approval uses Decionis Presence instead.", 9.4)
    d.note(end + 78, "No permission is created by a tap alone", "BLOCK stops submission. ESCALATE stays held. If the intent or evidence expires, obtain a fresh intent and approval as required. Successful presence must satisfy the bank's policy before ALLOW.", h=79)

    d.begin("Phase 2 | Issuer authorization", "Match locally. Claim once.", "The issuer asks about the authorization it received. The matcher runs in the bank; claiming the grant is a call to the configured authority, or a local claim at the edge when the budget demands it.")
    end = d.sequence(228, ["Card network", "Issuer hook", "AgentSafe", "Decionis"], [
        (0, 1, "1. Authorization arrives"),
        (1, 2, "2. Ask for grant match"),
        (2, 2, "3. Check fields + expiry"),
        (2, 3, "4. Claim single-use grant"),
        (3, 2, "5. Bound claim / refusal"),
        (2, 1, "6. APPROVE or NO_MATCH"),
        (1, 0, "7. Issuer approves / declines"),
    ], bank_lanes=(1, 2), row_height=35)
    d.label(end + 17, "Every match must satisfy the same purchase")
    d.text(MARGIN, end + 41, CONTENT, "Exact issuer token reference, currency and merchant id; exact merchant category when the purchase specified one; positive amount no greater than the granted ceiling; unexpired, unused grant. The grant is cryptographically verified and claimed against its original intent.", 9.5)
    d.note(end + 112, "APPROVE is the intent leg of the issuer's decision", "The issuer still applies funds, fraud and other card controls. NO_MATCH means usable authority was not established; it can reflect missing state, mismatch, expiry or claim failure. It does not prove the cardholder was absent.", h=81)
    d.text(MARGIN, end + 207, CONTENT, "Budget for the hook's answer at the 99th percentile: 150 ms with the hosted authority in the same cloud region, 300 ms across regions, 10 ms with a local claim at the edge; the in-process match is under a millisecond, and each is confirmed on the bank's own link before enforcement. Define an explicit NO_MATCH and timeout policy; strict enforcement must not silently bypass a required grant.", 9, MUTED)

    d.begin("Phase 2 | Where a tap can wait", "Three places, three taps", "An authorization lives on a clock measured in seconds, so where a held item waits while a person answers is a design decision per bank. Koard's paper names three places and three taps; this is what each is on AgentSafe.")
    y = d.table(232, [118, 110, CONTENT - 228], ["WHERE THE ITEM WAITS", "KOARD'S NAME", "WHAT AGENTSAFE DOES"], [
        ("Before the authorization exists", "Tap to Verify, for a held purchase", "The agent proposes, policy holds the grant or asks for the cardholder, the tap resumes the hold, the authorization matches it in milliseconds. The cleanest path, and the one built first."),
        ("In the bank's fraud queue", "Tap to Verify, for a flagged authorization", "EXECUTOR_CARD_NO_GRANT=evaluate: an authorization with no hold is evaluated at the commit boundary. ALLOW is held and claimed in the same call; ESCALATE is answered PENDING with the handoff, the platform pends the authorization, the tap arrives through POST /v1/escalations, and the re-presented authorization matches the hold the tap left. Needs a platform that can pend."),
        ("After the authorization", "Tap to Confirm, called by the platform", "Nothing can pend, so the authorization goes through and the cardholder confirms or rejects it afterwards in the issuer's app; a rejection is a reversal the bank's own rail carries. AgentSafe's part is evidence only: the same evaluation in SHADOW records what policy would have said, and the ISO 8583 interceptor's shadow mode records it on the wire. The easiest to build and the weakest: the money has moved."),
        ("A standing permission, no amount behind it", "Tap to Authenticate", "Not a purchase: the cardholder grants an agent permission to buy on their behalf, a new device, account recovery. A signal policy requires rather than an intent to hold, named in required_signals under the admission pattern; a producer's own signature on that signal is not verified today."),
    ], size=8.6)
    h = d.note(y + 14, "The fraud-queue contract", "A PENDING answer carries the authorization id, the intent id and hash, the decision and dossier ids, expires_at and the escalation handoff; Decionis tells the subscriber at the same moment. The issuer app's backend, an operator holding escalations.resume, presents the tap; the platform then re-presents the same authorization, which is approved, claimed once and settled by its result. Re-presented before the tap it is PENDING again from the same intent; past expires_at it is evaluated afresh; a result for a PENDING authorization is refused as unknown.")
    d.text(MARGIN, y + 26 + h, CONTENT, "Soft decline and re-present is left off on purpose, as Koard's paper leaves it off: the step-up it invites assumes a person at a browser.", 9, MUTED)

    d.begin("Contracts | Integration handoffs", "Name the receiving boundary", "These are separate interfaces. The issuer's hook calls AgentSafe's trusted executor; it does not call the generic proxy's control routes.")
    y = d.table(230, [100, 210, CONTENT - 310], ["CALLER / RECEIVER", "CONTRACT", "PURPOSE"], [
        ("Agent to AgentSafe", "POST /v1/actions<br/><b>PROPOSER</b>", "card.purchase with target card:&lt;token ref&gt;"),
        ("AgentSafe to Decionis", "POST /v1/authority/<br/>enforce-and-bind", "Evaluate the captured intent; return a decision and grant if allowed."),
        ("Decionis to subscriber", "authority.escalation_required", "Notify the bank-configured endpoint for the Koard journey."),
        ("Issuer app to AgentSafe", "POST /v1/escalations<br/><b>OPERATOR: escalations.resume</b>", "Resume the same intent with the signed presence attestation; the proposer may also present it."),
        ("Issuer hook to AgentSafe", "POST /v1/card-authorizations<br/><b>OPERATOR: cards.authorize</b>", "Match request fields and claim one bound grant; with no hold, evaluate at the commit boundary and answer APPROVE, PENDING or NO_MATCH."),
        ("AgentSafe to Decionis", "POST /v1/execution/claim-token", "Consume authority once, subject to validity and current checks."),
        ("Issuer hook to AgentSafe", "POST /v1/card-authorizations/<br/>{authorization_id}/result", "Report the issuer result for comparison and finalization."),
        ("Bank operator to AgentSafe", "POST /v1/control/halt<br/><b>OPERATOR: halt</b>", "The stop: no new work; the hook answers NO_MATCH with EXECUTOR_HALTED."),
    ], size=8.7)
    d.note(y + 19, "Bind the same identifiers through every handoff", "Carry tenant, intent id/hash, decision, dossier and grant bindings. Use a stable issuer authorization id: identical concurrent retries share one claim and answer, and a changed request under the same id is refused. The actor submitting a purchase must not hold issuer-authorization authority: separate principals, the processor credential restricted to cards.authorize, the issuer app to escalations.resume.")

    d.begin("Evidence | Presence and effect", "Keep proof and outcome distinct", "Koard proves presence for the purchase. The issuer reports the card decision. Decionis records the authority decision; AgentSafe links the observed effect.")
    d.label(228, "Presence attestation: the Decionis-side contract")
    d.text(MARGIN, 252, CONTENT, "Compact JWS with alg=EdDSA, typ=decionis-presence-attestation+jwt and the registered kid. The bank admits Koard's key and issuer identity. Align Koard's native output with this contract in the joint integration.", 9.4)
    y = d.table(310, [144, CONTENT - 144], ["CLAIMS", "BINDING"], [
        ("iss, aud, sub", "Registered provider; bank organization; opaque cardholder/token reference, never a PAN."),
        ("intent_id, intent_hash", "The exact purchase being approved. Another purchase requires its own bound evidence."),
        ("iat, exp, jti", "Issued time, expiry and unique attestation id; declared lifetime at most 300 seconds. Agree clock-skew tolerance."),
        ("presence", "method=card_tap; result=VERIFIED; approver_role=cardholder. Optional card_token_ref, token_match and network_validated."),
    ], size=9)
    d.label(y + 22, "Issuer result: the current AgentSafe endpoint")
    d.code(y + 47, 'POST /v1/card-authorizations/auth_ref_demo/result\n{\n  "status": "APPROVED",\n  "approved_amount_minor": 4000,\n  "auth_code": "A7"\n}', 106)
    d.text(MARGIN, y + 168, CONTENT, "The endpoint authenticates an issuer operator and accepts structured JSON. It does not accept an issuer-signed result JWS. AgentSafe builds effect evidence from this report and submits finalization; a cryptographic issuer receipt requires a separately agreed connector contract.", 9.3)
    d.text(MARGIN, y + 227, CONTENT, "Approved amounts within the purchase ceiling match; excess is an effect mismatch and halts by default. DECLINED records failure. A result after the claim lease is indeterminate, with reconciliation required.", 9.3, MUTED)

    d.begin("Joint delivery | Acceptance", "Close the issuer integration", "The core card flow exists in AgentSafe source. Production acceptance depends on the Koard ceremony, bank policy and the processor's actual authorization hook working together.")
    y = d.table(237, [112, CONTENT - 112], ["WORKSTREAM", "ACCEPTANCE EVIDENCE"], [
        ("Koard + issuer app", "Demonstrate the purchase shown to the cardholder, proof-to-card/token binding, signed handoff, failed/abandoned verification, expiry and key rotation."),
        ("Decionis + bank risk", "Register the producer key or admit Koard from the directory; admit the required presence facts; prove re-evaluation after evidence; test mismatched tenant/intent and revoked keys."),
        ("Issuer / processor", "Agree token and merchant mapping, real-time hook, deadline, NO_MATCH and PENDING handling, duplicate authorization handling and final result reporting."),
        ("Bank platform", "Separate identities, restrict bypass paths, require durable evidence, share the hold store across replicas, exercise restart, recovery and the stop."),
        ("Joint validation", "Run normal purchase, BLOCK, ESCALATE, PENDING in the fraud queue, changed amount/merchant, expired grant, duplicate claim, identifier collision and unknown outcome end to end."),
    ], size=9.4)
    h = d.note(y + 21, "Limits that shape the rollout", "One pending purchase per card per merchant. Split authorizations are not offered; incremental ones are, per deployment, from the same claim within the ceiling. Rotating the hold key drains holds rather than re-sealing them. Velocity is counted by AgentSafe per card; a producer's own signature on a standing signal (Tap to Authenticate) is not verified today.")
    y += 21 + h + 14
    h = d.text(MARGIN, y, CONTENT, "Where the authority and Presence run per hosting tier, and whose custody each key is in, is written once: docs/gateway/deployment.md in the AgentSafe repository and decionis.com/docs/card-authorization. A local claim at the edge removes the hook's network call when the replay store is the shared Postgres one, the evidence chain is retained and signed, and the bundle and usage-report keys live in the bank's key vault.", 9.2, MUTED)
    d.text(MARGIN, y + h + 12, CONTENT, "Review basis: Koard's workflow review of 8 October, the design-partner context and AgentSafe at its 12 October revision (holds by card and merchant, the shared hold store, the commit-boundary evaluation and the hosting answers). Decionis-side attestation, admission and managed-escalation contracts were checked in source; live service availability and issuer integration were not tested.", 8.3, MUTED)
    return d.save()


FONT_DIRS = (
    Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/libreoffice-headless/libreoffice/LibreOfficeDev.app/Contents/Resources/fonts/truetype",
    Path("/Applications/LibreOffice.app/Contents/Resources/fonts/truetype"),
)


def default_font_dir():
    """The first bundled font directory that has the Noto Sans face; --font-dir overrides it."""
    for candidate in FONT_DIRS:
        if (candidate / "NotoSans-Regular.ttf").exists():
            return candidate
    return FONT_DIRS[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "output/pdf")
    parser.add_argument("--only", choices=("all", "banks", "joint"), default="all")
    parser.add_argument("--font-dir", type=Path, default=default_font_dir())
    args = parser.parse_args()
    for name, filename in [("Decionis", "NotoSans-Regular.ttf"), ("DecionisBold", "NotoSans-Bold.ttf"), ("DecionisMono", "DejaVuSansMono.ttf")]:
        pdfmetrics.registerFont(TTFont(name, str(args.font_dir / filename)))
    pdfmetrics.registerFontFamily("Decionis", normal="Decionis", bold="DecionisBold", italic="Decionis", boldItalic="DecionisBold")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output / "manifest.json"
    previous = json.loads(manifest_path.read_text())["outputs"] if manifest_path.exists() else []
    rebuilt = []
    if args.only in ("all", "banks"):
        rebuilt.append(bank_brief(args.output))
    if args.only in ("all", "joint"):
        rebuilt.append(joint_brief(args.output))
    by_file = {entry["file"]: entry for entry in previous + rebuilt}
    results = [by_file[name] for name in (
        "AgentSafe-for-banks.pdf", "Koard-and-Decionis-agentic-authorization-design-flow.pdf"
    ) if name in by_file and (args.output / name).exists()]
    manifest = {
        "review_date": "2026-10-12", "baseline": "19453788", "gateway_revision": "19453788", "outputs": results,
        "brand": {"navy": NAVY, "audit_purple": PURPLE, "trust_blue": BLUE, "logo": "docs/banking/assets/Decionis.png"},
        "renderer": "ReportLab; embedded fonts; vector flow diagrams",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(rebuilt, indent=2))


if __name__ == "__main__":
    main()
