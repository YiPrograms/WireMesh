import type { ClientConfigModel } from "../types";

export const PRIVATE_KEY_PLACEHOLDER = "<CLIENT_PRIVATE_KEY>";

export function renderConfig(
  model: ClientConfigModel,
  privateKey?: string,
): string {
  const lines = [
    "[Interface]",
    `PrivateKey = ${privateKey || PRIVATE_KEY_PLACEHOLDER}`,
    `Address = ${model.address}/32`,
  ];
  const dns = [...model.options.dns_servers, ...model.options.search_domains];
  if (dns.length) lines.push(`DNS = ${dns.join(", ")}`);
  if (model.options.mtu) lines.push(`MTU = ${model.options.mtu}`);
  const peers = [...model.peers].sort((a, b) =>
    a.site_name.localeCompare(b.site_name),
  );
  for (const peer of peers) {
    lines.push(
      "",
      "[Peer]",
      `# ${peer.site_name}`,
      `PublicKey = ${peer.public_key}`,
      `Endpoint = ${peer.endpoint}`,
      `AllowedIPs = ${peer.allowed_ips.join(", ")}`,
    );
    if (model.options.persistent_keepalive) {
      lines.push(
        `PersistentKeepalive = ${model.options.persistent_keepalive}`,
      );
    }
  }
  return `${lines.join("\n")}\n`;
}

export function downloadText(filename: string, contents: string): void {
  const blob = new Blob([contents], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
