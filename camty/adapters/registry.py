"""适配器注册表。新增适配器在此登记。"""

from __future__ import annotations

from camty.adapters.base import ToolAdapter
from camty.adapters.authz_probe import AuthzProbeAdapter
from camty.adapters.browser import BrowserActionAdapter, BrowserVisitAdapter
from camty.adapters.c2 import C2CollectAdapter, C2SessionsAdapter, C2TaskAdapter
from camty.adapters.code_audit import CodeAuditAdapter
from camty.adapters.cred_test import CredTestAdapter
from camty.adapters.cve_intel import CveIntelAdapter
from camty.adapters.evidence_search import EvidenceSearchAdapter
from camty.adapters.hashcrack import HashcrackAdapter
from camty.adapters.fscan import FscanAdapter
from camty.adapters.httpx import HttpxAdapter
from camty.adapters.impacket import (
    AdComputersAdapter,
    AdUsersAdapter,
    AsRepRoastAdapter,
    DelegationFindAdapter,
    GppPasswordAdapter,
    KeylistAdapter,
    LapsReadAdapter,
    MachineAccountAdapter,
    NtlmRelayAdapter,
    RbcdAdapter,
    SamrEnumAdapter,
    SecretsDumpAdapter,
    TicketerAdapter,
)
from camty.adapters.inj_probe import InjProbeAdapter
from camty.adapters.mail_code import MailCodeAdapter
from camty.adapters.osint import OsintAdapter
from camty.adapters.scopesentry_sync import ScopeSentrySyncAdapter
from camty.adapters.js_recon import JsReconAdapter
from camty.adapters.kerberoast import KerberoastAdapter
from camty.adapters.lateral import LateralMoveAdapter
from camty.adapters.nuclei import NucleiAdapter
from camty.adapters.recon_web import DirScanAdapter, SecretScanAdapter
from camty.adapters.smb_enum import SmbEnumAdapter
from camty.adapters.sqli_exploit import SqliExploitAdapter
from camty.adapters.sqli_probe import SqliProbeAdapter
from camty.adapters.subfinder import SubfinderAdapter
from camty.report import ReportAdapter

_ADAPTERS: list[ToolAdapter] = [
    SubfinderAdapter(),
    HttpxAdapter(),
    NucleiAdapter(),
    SecretScanAdapter(),
    DirScanAdapter(),
    JsReconAdapter(),
    EvidenceSearchAdapter(),
    CveIntelAdapter(),
    HashcrackAdapter(),
    OsintAdapter(),
    BrowserVisitAdapter(),
    BrowserActionAdapter(),
    SqliProbeAdapter(),
    SqliExploitAdapter(),
    InjProbeAdapter(),
    AuthzProbeAdapter(),
    MailCodeAdapter(),
    ScopeSentrySyncAdapter(),
    CodeAuditAdapter(),
    FscanAdapter(),
    SmbEnumAdapter(),
    KerberoastAdapter(),
    AsRepRoastAdapter(),
    AdUsersAdapter(),
    AdComputersAdapter(),
    SamrEnumAdapter(),
    DelegationFindAdapter(),
    SecretsDumpAdapter(),
    LapsReadAdapter(),
    GppPasswordAdapter(),
    KeylistAdapter(),
    MachineAccountAdapter(),
    RbcdAdapter(),
    NtlmRelayAdapter(),
    TicketerAdapter(),
    CredTestAdapter(),
    LateralMoveAdapter(),
    C2SessionsAdapter(),
    C2TaskAdapter(),
    C2CollectAdapter(),
    ReportAdapter(),
]

REGISTRY: dict[str, ToolAdapter] = {a.name: a for a in _ADAPTERS}
