import { ZodError } from "zod";
import { ApiError } from "./auth";

export function apiFailure(error: unknown): Response {
  if (error instanceof ApiError) {
    return Response.json({ error: { code: error.code, message: error.message } }, { status: error.status });
  }
  if (error instanceof ZodError) {
    return Response.json(
      { error: { code: "INVALID_REQUEST", message: "The request body is invalid.", issues: error.issues } },
      { status: 400 },
    );
  }
  const message = error instanceof Error ? error.message : "An unexpected error occurred.";
  const configurationFailure = message.startsWith("DATABASE_URL is required");
  return Response.json(
    {
      error: {
        code: configurationFailure ? "DATABASE_NOT_CONFIGURED" : "INTERNAL_ERROR",
        message: configurationFailure ? message : "The request could not be completed.",
      },
    },
    { status: configurationFailure ? 503 : 500 },
  );
}

export async function readJson(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    throw new ApiError(400, "A valid JSON body is required.", "INVALID_JSON");
  }
}
