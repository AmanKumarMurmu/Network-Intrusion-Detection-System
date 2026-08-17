import { useEffect, useState } from "react";
import { Radar, ShieldCheck } from "lucide-react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "@/integrations/supabase/client";

export function useSupabaseSession() {
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setReady(true);
    });
    const { data: sub } = supabase.auth.onAuthStateChange((_event, next) => {
      setSession(next);
      setReady(true);
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  return { session, ready };
}

export function AuthGate() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    const fn =
      mode === "signin"
        ? supabase.auth.signInWithPassword({ email, password })
        : supabase.auth.signUp({
            email,
            password,
            options: { emailRedirectTo: window.location.origin },
          });
    const { error } = await fn;
    if (error) setMessage(error.message);
    else if (mode === "signup") setMessage("Check your inbox to confirm the account.");
    setBusy(false);
  };

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="panel glow w-full max-w-md p-6">
        <div className="flex items-center gap-3">
          <div className="flex size-11 items-center justify-center rounded-xl border border-primary/40 bg-primary/10">
            <Radar className="size-5 text-primary" aria-hidden />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight">Sentinel NIDS</h1>
            <p className="text-xs text-muted-foreground">Analyst console — authorized access only</p>
          </div>
        </div>

        <p className="mt-4 flex items-start gap-2 rounded-lg border border-border bg-surface-2 p-3 text-xs text-muted-foreground">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
          Detection logs contain internal network topology and sensor coverage, so they are only
          visible to signed-in analysts.
        </p>

        <form onSubmit={submit} className="mt-5 space-y-3">
          <div>
            <label className="label-mono" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mt-1 w-full rounded-md border border-border bg-background/60 px-3 py-2 font-mono text-sm outline-none focus:border-ring"
            />
          </div>
          <div>
            <label className="label-mono" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full rounded-md border border-border bg-background/60 px-3 py-2 font-mono text-sm outline-none focus:border-ring"
            />
          </div>

          {message ? <p className="text-xs text-muted-foreground">{message}</p> : null}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-md bg-primary px-3 py-2 font-mono text-xs uppercase tracking-wider text-primary-foreground disabled:opacity-60"
          >
            {mode === "signin" ? "Sign in" : "Create account"}
          </button>
        </form>


        <button
          onClick={() => setMode(mode === "signin" ? "signup" : "signin")}
          className="mt-4 w-full text-center text-xs text-muted-foreground underline-offset-4 hover:underline"
        >
          {mode === "signin" ? "Need an account? Sign up" : "Already have an account? Sign in"}
        </button>
      </div>
    </main>
  );
}
