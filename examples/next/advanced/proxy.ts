import { NextResponse, type NextRequest } from "next/server.js";
import { auth } from "./auth.js";

export const proxy = async (request: NextRequest) => {
    const renewal = await auth.renew({
        request,
        response: NextResponse.next(),
        unauthorizedUrl: "/auth/login",
    });

    if (renewal.status !== null && renewal.status >= 500) {
        return NextResponse.redirect(new URL("/maintenance", request.url));
    }

    return renewal.response;
};

export const config = {
    matcher: ["/account/:path*", "/dashboard/:path*"],
};
