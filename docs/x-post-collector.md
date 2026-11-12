# X post URL collector

This optional local tool opens nine public profiles in a dedicated Chromium
session and saves only post URLs to the sibling dashboard's `x-posts.json`.
It does not copy credentials into the repository. It stops on login challenges
or blocked pages and keeps the last saved URLs for failed accounts.

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-x-collector.txt
.venv\Scripts\python.exe -m playwright install chromium
.venv\Scripts\python.exe scripts\collect_x_post_urls.py --login
.venv\Scripts\python.exe scripts\collect_x_post_urls.py
```

The login step is interactive and uses `~/.boannews-x-profile` as its local
browser profile. Close other runs before starting a new one. Review the JSON
diff before committing it to the dashboard repository. Running the collector
locally does not deploy changes; the dashboard repository must be pushed.

X may restrict scripted profile access. This tool does not bypass rate limits,
CAPTCHAs, or other access controls. Do not configure unattended recurring runs
without reviewing X's current terms and operational risk.
