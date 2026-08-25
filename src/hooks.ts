/**
 * Explicit tenant path routing. The server handle still reads the original URL
 * to resolve the tenant; this hook only removes the prefix before SvelteKit
 * matches the application route.
 */
export function reroute({ url }: { url: URL }): string | void {
    const match = /^\/t\/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\/.*)?$/i.exec(url.pathname);
    if (!match) return;
    return match[1] || "/";
}
