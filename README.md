# November Warriors — Friends Challenge

A mobile-friendly Supabase-powered habit and streak challenge for friend groups.

## Files
- `index.html` — the web app.
- `schema.sql` — Supabase tables, Row Level Security, group invite-code function and leaderboard view.

## Supabase setup
1. Open your Supabase project → SQL Editor → New query.
2. Copy all of `schema.sql` into the editor and run it.
3. Confirm the Project URL and publishable key in the constants near the top of `index.html`.
4. In Authentication → URL Configuration, set your deployed website URL and add it to the redirect URLs.
5. Email/password sign-in is supported. Google sign-in is optional and requires setup under Authentication → Providers.
6. Deploy `index.html` to GitHub Pages, Netlify or another static host.

## First use
1. Create an account and sign in.
2. Create a friends group; the creator is automatically added as its owner.
3. Create a challenge and share the invite code.
4. Each friend creates personal daily goals and checks them off. The leaderboard totals points.

## Security and scope
- Row Level Security is enabled. Group members can see group activity and leaderboard data; users manage their own goals and check-ins.
- The browser publishable key is designed for client-side use. Never place a Supabase secret or service-role key in `index.html`.
- The SQL is an MVP starting point; test it in your Supabase project before inviting users.
- The activity feed loads on page refresh or after app actions; the current frontend does not subscribe to Realtime events.
