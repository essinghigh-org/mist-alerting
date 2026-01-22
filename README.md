## Juniper Mist Alert API --> Elasticsearch Pipeline

I was recently faced with a little issue requiring this script as, frankly, webhooks suck when using an internal Elasticsearch instance.

Usage: `python3 fetch_alarms.py`

It's pretty simple. No real magic involved. Populate `.env` with:
*  `ES_USER`, `ES_PASS`, `ES_URL` for Elasticsearch
* `MIST_API_KEY`, `MIST_PROD_ORG_ID` for Juniper Mist

It will fetch the last thirty minutes, map the site IDs to names, map the alert IDs to names, and then send it all neatly-packaged to Elasticsearch. The index name is `mist-alerting` by default. Couldn't be bothered to make it an env var.

I'm running this internally on a cronjob of `*/2 * * * *` - you might be asking yourself "you're fetching every two minutes, so why are you fetching half an hour each time?"

Because the alerting is slow. The alerts don't show up in the API for about 10 minutes until after they've actually happened. So, rather than using a sliding-window, I'm forced to store the last alarm's timestamp in a text file, then refer to it when sending new events to Elasticsearch.

No support will be given for this, it's public purely because I couldn't find anything similar.