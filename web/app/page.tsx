import { Hero } from "@/components/sections/Hero";
import { AccuracySection } from "@/components/sections/AccuracySection";
import { TrustStack } from "@/components/sections/TrustStack";
import { SiteFooter } from "@/components/sections/SiteFooter";
import { VerifiableAudit } from "@/components/verifiable-audit/VerifiableAudit";
import { site, citationsByRecord } from "@/lib/site-data";

export default function Page() {
  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200">
      <Hero />
      <section id="verify" className="mx-auto max-w-3xl px-6 py-12">
        <h2 className="mb-2 text-2xl font-semibold text-neutral-100">{String(site.meta.host)} — confirmed compromised</h2>
        <p className="mb-6 text-neutral-400">{site.verdict.executive_summary.split(". ").slice(0, 2).join(". ")}.</p>
        <VerifiableAudit audit={site.audit} citations={citationsByRecord()} />
      </section>
      <AccuracySection />
      <TrustStack />
      <SiteFooter />
    </main>
  );
}
