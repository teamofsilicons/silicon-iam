import { fail, type Settings } from "./session.ts";

/** A fixed, read-only adapter. Credentials live only for this request. */
export async function testApplicationView(
  body: Uint8Array,
  config: Settings,
): Promise<Response> {
  let input: unknown;
  try {
    input = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return fail(
      "invalid_test_credentials",
      "Enter the test app secret and IAM test key.",
      400,
    );
  }
  if (!input || typeof input !== "object")
    return fail(
      "invalid_test_credentials",
      "Enter the test app secret and IAM test key.",
      400,
    );
  const { app_id, app_secret, iam_test_key } = input as Record<string, unknown>;
  if (
    typeof app_id !== "string" ||
    !/^[a-z][a-z0-9_-]{0,79}$/.test(app_id) ||
    app_id.length > 200 ||
    typeof app_secret !== "string" ||
    !/^[\x21-\x7e]{16,512}$/.test(app_secret) ||
    typeof iam_test_key !== "string" ||
    !/^[\x21-\x7e]{16,512}$/.test(iam_test_key)
  )
    return fail(
      "invalid_test_credentials",
      "Enter a valid app ID, test app secret, and IAM test key.",
      400,
    );
  try {
    const response = await fetch(
      new URL("/api/v1/application/testing-context", config.upstream),
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          "Silicon-IAM-Supported-API-Versions": "v1",
          Authorization: `Basic ${btoa(`${app_id}:${app_secret}`)}`,
          "X-Testing-Environment-Key": iam_test_key,
        },
        redirect: "error",
        signal: AbortSignal.timeout(20000),
      },
    );
    if (!response.ok) {
      if ([401, 403, 404].includes(response.status))
        return fail(
          "invalid_test_credentials",
          "The app secret or IAM test key is invalid for this application. Use its test secret, not its production secret.",
          422,
        );
      return fail(
        "test_view_unavailable",
        "The test application could not be loaded. Try again.",
        502,
      );
    }
    return Response.json(await response.json(), {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return fail(
      "test_view_unavailable",
      "The test application could not be loaded. Try again.",
      502,
    );
  }
}
