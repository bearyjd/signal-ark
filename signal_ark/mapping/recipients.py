"""Build AccountData, Self, Contact, and Group recipient frames from Desktop conversations."""

from __future__ import annotations

from signal_ark.mapping.ids import IdAllocator
from signal_ark.mapping.util import _b64_to_bytes, _normalize_aci, _uuid_str_to_bytes
from signal_ark.proto.Backup_pb2 import (
    AccountData,
    Contact,
    Frame,
    Group,
    Self as SelfRecipient,
)


def build_account_frame(seed_account: AccountData) -> Frame:
    """Use the seed backup's AccountData as-is (has correct registration info)."""
    frame = Frame()
    frame.account.CopyFrom(seed_account)
    return frame


def build_self_recipient(
    ids: IdAllocator,
    self_conversation_id: str,
    self_aci: str | None = None,
) -> Frame:
    """Build the Self recipient frame.

    Registers the recipient under both the "__self__" placeholder and the
    real ACI so quotes/reactions authored by us resolve to this recipient.
    """
    rid = ids.alloc_recipient(self_conversation_id, service_id="__self__")
    if self_aci:
        ids.alias_service_id(self_aci, rid)
    frame = Frame()
    frame.recipient.id = rid
    frame.recipient.self.CopyFrom(SelfRecipient())
    return frame


def build_contact_recipient(
    ids: IdAllocator,
    conv: dict,
    conv_id: str,
) -> Frame | None:
    """Build a Contact recipient frame from a Desktop conversation row."""
    service_id = conv.get("serviceId")
    if not service_id:
        return None

    rid = ids.alloc_recipient(conv_id, service_id=service_id)

    frame = Frame()
    frame.recipient.id = rid

    contact = frame.recipient.contact

    # ACI
    aci_str = service_id
    if aci_str and not aci_str.startswith("PNI:"):
        try:
            contact.aci = _uuid_str_to_bytes(aci_str)
        except ValueError:
            pass

    # PNI
    pni_str = conv.get("pni")
    if pni_str:
        if pni_str.startswith("PNI:"):
            pni_str = pni_str[4:]
        try:
            contact.pni = _uuid_str_to_bytes(pni_str)
        except ValueError:
            pass

    # E164
    e164 = conv.get("e164")
    if e164:
        e164_num = e164.replace("+", "")
        if e164_num.isdigit():
            contact.e164 = int(e164_num)

    # Profile
    profile_key = _b64_to_bytes(conv.get("profileKey"))
    if profile_key:
        contact.profileKey = profile_key

    contact.profileSharing = bool(conv.get("profileSharing"))
    contact.profileGivenName = conv.get("profileName") or ""
    contact.profileFamilyName = conv.get("profileFamilyName") or ""
    contact.systemGivenName = conv.get("systemGivenName") or ""
    contact.systemFamilyName = conv.get("systemFamilyName") or ""

    # Identity key
    identity_key = _b64_to_bytes(conv.get("identityKey"))
    if identity_key:
        contact.identityKey = identity_key

    # Registration status
    contact.registered.CopyFrom(Contact.Registered())

    # Blocked
    contact.blocked = bool(conv.get("isBlocked"))

    return frame


def build_member_recipient(ids: IdAllocator, aci: str) -> Frame | None:
    """Build a minimal registered Contact recipient for a group member with no conversation."""
    canonical = _normalize_aci(aci)
    if canonical is None:
        return None

    rid = ids.alloc_recipient(canonical, service_id=canonical)

    frame = Frame()
    frame.recipient.id = rid
    contact = frame.recipient.contact
    contact.aci = _uuid_str_to_bytes(canonical)
    contact.registered.CopyFrom(Contact.Registered())
    return frame


def _map_story_send_mode(mode_str: str | None) -> int:
    if mode_str == "Never":
        return Group.StorySendMode.DISABLED
    if mode_str == "Always":
        return Group.StorySendMode.ENABLED
    return Group.StorySendMode.DEFAULT


def build_group_recipient(
    ids: IdAllocator,
    conv: dict,
    conv_id: str,
) -> Frame | None:
    """Build a Group recipient frame from a Desktop group conversation."""
    ids.group_conversations.add(conv_id)
    master_key = _b64_to_bytes(conv.get("masterKey"))
    if not master_key:
        return None

    rid = ids.alloc_recipient(conv_id)

    frame = Frame()
    frame.recipient.id = rid

    group = frame.recipient.group
    group.masterKey = master_key
    group.whitelisted = bool(conv.get("profileSharing"))
    group.hideStory = bool(conv.get("hideStory"))
    group.storySendMode = _map_story_send_mode(conv.get("storySendMode"))
    group.blocked = bool(conv.get("isBlocked"))

    snapshot = group.snapshot
    snapshot.version = int(conv.get("revision") or 0)
    snapshot.announcements_only = bool(conv.get("announcementsOnly"))

    # Title
    name = conv.get("name")
    if name:
        snapshot.title.title = name

    # Disappearing messages timer
    expire_timer = conv.get("expireTimer")
    if expire_timer:
        snapshot.disappearingMessagesTimer.disappearingMessagesDuration = int(expire_timer)

    # Access control
    ac = conv.get("accessControl")
    if ac:
        snapshot.accessControl.attributes = int(ac.get("attributes", 0))
        snapshot.accessControl.members = int(ac.get("members", 0))
        snapshot.accessControl.addFromInviteLink = int(ac.get("addFromInviteLink", 0))

    # Members
    for m in conv.get("membersV2") or []:
        try:
            user_id = _uuid_str_to_bytes(m.get("aci") or "")
        except ValueError:
            continue
        member = snapshot.members.add()
        member.userId = user_id
        member.role = int(m.get("role", 1))
        member.joinedAtVersion = int(m.get("joinedAtVersion", 0))

    return frame
