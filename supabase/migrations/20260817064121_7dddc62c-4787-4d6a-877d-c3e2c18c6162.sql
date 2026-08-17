DROP POLICY IF EXISTS "Anyone can view security events" ON public.security_events;
CREATE POLICY "Signed-in users can view security events"
ON public.security_events FOR SELECT TO authenticated USING (true);
REVOKE ALL ON public.security_events FROM anon;
GRANT SELECT ON public.security_events TO authenticated;
GRANT ALL ON public.security_events TO service_role;