"use server";

import {
  digestCapability,
  isCapabilityToken,
} from "@/lib/emergency/capability";
import { sendEmergencyContactNotification } from "@/lib/emergency/notify-contacts";
import { logError } from "@/lib/logging/logger";
import { createClient } from "@/lib/supabase/server";

export type NotifyContactsState = {
  status?: "sent" | "error";
  error?: string;
};

const REASON_MESSAGES: Record<string, string> = {
  NOT_OPTED_IN: "This patient has not opted in to emergency contact notifications.",
  RATE_LIMITED:
    "A notification was already sent recently for this card. Please wait before sending another.",
  PRESENCE_REQUIRED: "Please reload this card, then try again.",
  NO_CONTACTS: "No emergency contacts are available for this patient.",
  INVALID_INPUT: "Facility name is too long.",
  NOT_FOUND: "This link is no longer valid.",
};

/**
 * Issue #542: server action behind the responder-facing "Notify emergency
 * contacts" button. All abuse/consent gating (proof-of-presence, patient
 * opt-in, and the 30-minute rate limit) is enforced server-side inside the
 * notify_emergency_contacts() RPC, not here -- this action only shapes the
 * form input/output and calls the (currently stubbed) send function.
 */
export async function notifyEmergencyContacts(
  _previous: NotifyContactsState | undefined,
  formData: FormData,
): Promise<NotifyContactsState> {
  void _previous;
  const token = formData.get("token");
  if (typeof token !== "string" || !isCapabilityToken(token)) {
    return { status: "error", error: "This link is no longer valid." };
  }

  const facilityNameRaw = formData.get("facilityName");
  const facilityName =
    typeof facilityNameRaw === "string" && facilityNameRaw.trim()
      ? facilityNameRaw.trim().slice(0, 120)
      : null;

  const supabase = await createClient();
  const { data, error } = await supabase
    .rpc("notify_emergency_contacts", {
      p_token_digest: digestCapability(token),
      p_facility_name: facilityName,
    })
    .single();

  if (error) {
    logError("Failed to notify emergency contacts", error, {
      route: "/card/c/[token] (action: notifyEmergencyContacts)",
    });
    return {
      status: "error",
      error: "Something went wrong. Please try again.",
    };
  }

  if (!data.allowed || !data.contacts) {
    return {
      status: "error",
      error: REASON_MESSAGES[data.reason] ?? "This link is no longer valid.",
    };
  }

  await sendEmergencyContactNotification({
    contacts: data.contacts,
    patientFirstName: data.patient_first_name,
    facilityName,
  });

  return { status: "sent" };
}
