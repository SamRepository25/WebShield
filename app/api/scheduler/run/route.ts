import { NextResponse } from "next/server";
import { runScheduler } from "@/lib/scheduler";

export async function GET() {
  try {
    const result = await runScheduler();

    return NextResponse.json(result);
  } catch (error) {
    console.error("Scheduler Error:", error);

    return NextResponse.json(
      {
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Unknown scheduler error",
      },
      {
        status: 500,
      }
    );
  }
}