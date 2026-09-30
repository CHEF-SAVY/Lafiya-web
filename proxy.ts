import { createServerClient } from "@supabase/ssr";
import { type NextRequest, NextResponse } from "next/server";

import { clientEnv } from "@/lib/env";

const PROTECTED_PREFIXES = ["/profile"];
const AUTH_ONLY_PATHS = ["/signin", "/signup"];

const CSP_REPORT_PATH = "/api/csp-report";
const CSP_REPORT_ENDPOINT_NAME = "csp-endpoint";

export async function proxy(request: NextRequest) {
  // Issue #520: this is a high-frequency, unauthenticated, browser-fired
  // endpoint -- it must never wait on (or be redirected by) the session
  // check below, so it is excluded from the whole auth pipeline, not just
  // the redirect logic.
  if (request.nextUrl.pathname === CSP_REPORT_PATH) {
    return NextResponse.next({ request });
  }

  let response = NextResponse.next({ request });

  const supabase = createServerClient(
    clientEnv.NEXT_PUBLIC_SUPABASE_URL,
    clientEnv.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value),
          );
          response = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            response.cookies.set(name, value, options),
          );
        },
      },
    },
  );

  // getUser() (not getSession()) revalidates the token against the auth
  // server on every request rather than trusting a potentially-stale JWT —
  // required reading before touching this: https://supabase.com/docs/guides/auth/server-side/nextjs
  const {
    data: { user },
  } = await supabase.auth.getUser();

  const { pathname } = request.nextUrl;
  const isPublicCard = pathname === "/card" || pathname.startsWith("/card/");

  if (isPublicCard) {
    // The URL is a bearer capability (legacy UUID or current capability). It
    // must never be sent as a referrer, placed in a shared CDN cache, indexed,
    // or allowed to trigger third-party network requests from the card page.
    response.headers.set("Referrer-Policy", "no-referrer");
    response.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
    response.headers.set("Cache-Control", "private, no-store, max-age=0");
    // Issue #520: report-to (Reporting API v1, via Reporting-Endpoints)
    // covers current browsers; report-uri stays alongside it for Safari,
    // which has never implemented the Reporting API. Both point at the
    // same PHI-safe-sampling endpoint.
    const reportUri = new URL(CSP_REPORT_PATH, request.url).toString();
    response.headers.set(
      "Reporting-Endpoints",
      `${CSP_REPORT_ENDPOINT_NAME}="${reportUri}"`,
    );
    response.headers.set(
      "Content-Security-Policy",
      `default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; connect-src 'self'; img-src 'self' data: blob: https://*.supabase.co http://127.0.0.1:54321; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; report-to ${CSP_REPORT_ENDPOINT_NAME}; report-uri ${reportUri}`,
    );
  }
  const isProtected = PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
  const isAuthOnly = AUTH_ONLY_PATHS.includes(pathname);

  if (!user && isProtected) {
    const signInUrl = new URL("/signin", request.url);
    signInUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(signInUrl);
  }

  if (user && isAuthOnly) {
    return NextResponse.redirect(new URL("/profile", request.url));
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for static assets and image
     * optimization files, so the session cookie still gets refreshed on
     * every navigable page without doing this work for every asset.
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
