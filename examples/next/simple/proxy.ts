import { NextResponse, type NextRequest } from "next/server.js";

import { auth } from "./auth.js";

export const proxy = async (request: NextRequest) => {
    const renewal = await auth.renew({
        request,
        response: NextResponse.next(),
        unauthorizedUrl: "/auth/login",
    });

    return renewal.response;
};

export const config = {
    matcher: ["/dashboard/:path*"],
};
