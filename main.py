import requests
import re
import os
from datetime import datetime, timedelta
import pytz

# GitHub API token (fetched from environment variable)
GITHUB_TOKEN = os.getenv('SCRAPE_TOKEN', 'default_token_if_not_set')
HEADERS = {'Authorization': f'token {GITHUB_TOKEN}'}

# Files for tracking and logging
LAST_PROCESSED_FILE = 'last_processed.txt'
SECRETS_LOG_FILE = 'secrets_found.log'

# Secret patterns to detect
SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
    r'gh[pousr]_[0-9a-zA-Z]{36}',  # GitHub Personal Access Token
    r'xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',  # Slack Token
    
    # Google Cloud Platform (GCP) credentials
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',  # GCP Project ID (UUID format)
    r'AIza[0-9A-Za-z-_]{35}',  # GCP API Key
    r'ya29\.[0-9A-Za-z-_]+',  # GCP OAuth 2.0 Access Token
    
    # Netflix/entertainment credentials (hypothetical)
    r'nf_[0-9a-zA-Z]{32}',  # Hypothetical Netflix API Key
    r'[0-9a-f]{32}',  # Generic 32-character hex token
    r'[A-Za-z0-9]{20,40}',  # Generic alphanumeric token (20-40 chars)

    # AI Platform API Keys
    r'sk-[0-9a-zA-Z]{24,48}',  # OpenAI/ChatGPT API Key (e.g., sk- followed by 24-48 chars)
    r'anthropic-[0-9a-zA-Z]{32}',  # Hypothetical Anthropic API Key (e.g., anthropic- prefix)
    r'ai-[0-9a-zA-Z]{32}',  # Hypothetical Google AI/MakerSuite API Key (e.g., ai- prefix)
    r'[0-9a-f]{40}',  # Generic 40-character hex token (common in AI platforms)
]

def get_last_processed_time():
    """Read the last processed timestamp from a file, ensuring UTC timezone."""
    if os.path.exists(LAST_PROCESSED_FILE):
        with open(LAST_PROCESSED_FILE, 'r') as f:
            try:
                dt = datetime.fromisoformat(f.read().strip())
                if dt.tzinfo is None:
                    dt = pytz.UTC.localize(dt)
                return dt
            except ValueError:
                pass
    return pytz.UTC.localize(datetime.utcnow() - timedelta(days=1))

def set_last_processed_time(timestamp):
    """Write the latest processed timestamp to a file."""
    with open(LAST_PROCESSED_FILE, 'w') as f:
        f.write(timestamp.isoformat())

def fetch_push_events(page=1):
    """Fetch a page of public push events from GitHub."""
    url = f'https://api.github.com/events?per_page=30&page={page}'
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def fetch_commit_details(owner, repo, sha):
    """Fetch commit details including the diff."""
    url = f'https://api.github.com/repos/{owner}/{repo}/commits/{sha}'
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def check_for_secrets(diff):
    """Check if the diff contains secrets and return them."""
    added_lines = [line for line in diff.split('\n') if line.startswith('+')]
    found_secrets = []
    for line in added_lines:
        for pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, line)
            if matches:
                found_secrets.extend(matches)
    return found_secrets

def log_secrets(repo, filename, sha, secrets):
    """Log detected secrets to a file."""
    with open(SECRETS_LOG_FILE, 'a') as f:
        timestamp = datetime.now(pytz.UTC).isoformat()
        for secret in secrets:
            f.write(f"{timestamp} | Repo: {repo} | File: {filename} | Commit: {sha} | Secret: {secret}\n")

def main():
    """Main function to detect and scrape secrets."""
    last_processed = get_last_processed_time()
    new_last_processed = last_processed
    page = 1

    while True:
        try:
            events = fetch_push_events(page)
            if not events:
                break

            for event in events:
                if event['type'] != 'PushEvent':
                    continue

                created_at = datetime.fromisoformat(event['created_at'].replace('Z', '+00:00'))
                if created_at <= last_processed:
                    break
                if created_at > new_last_processed:
                    new_last_processed = created_at

                repo = event['repo']['name']
                for commit in event['payload']['commits']:
                    sha = commit['sha']
                    try:
                        commit_details = fetch_commit_details(repo.split('/')[0], repo.split('/')[1], sha)
                        for file in commit_details['files']:
                            if 'patch' in file:
                                secrets = check_for_secrets(file['patch'])
                                if secrets:
                                    log_secrets(repo, file['filename'], sha, secrets)
                                    print(f"Secrets found in {repo}, file: {file['filename']}, commit: {sha}")
                    except requests.HTTPError as e:
                        print(f"Error fetching commit {sha}: {e}")

            page += 1
            if page > 10:
                break

        except requests.HTTPError as e:
            print(f"API error: {e}")
            break

    set_last_processed_time(new_last_processed)

if __name__ == '__main__':
    main()