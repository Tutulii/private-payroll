import { readPrivateExitReadiness } from "@/lib/server/private-exit-quote";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const readiness = await readPrivateExitReadiness();
    return Response.json({ readiness }, {
      status: 200,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return Response.json({
      readiness: {
        enabled: false,
        code: "ANONYMIZER_NOT_VERIFIED",
        message: error instanceof Error ? error.message : "Private-exit readiness is unavailable.",
      },
    }, { status: 503, headers: { "cache-control": "no-store" } });
  }
}
