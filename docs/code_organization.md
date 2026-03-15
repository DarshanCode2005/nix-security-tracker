# Code Organization and Best Practices

## Documentation Guidelines

- **One Sentence Per Line**: When writing or editing documentation, please reformat paragraphs so that there is exactly one sentence per line.
  This makes it a lot easier to make targeted suggestions in pull request reviews.
- **Authoritative Linking**: Always link names of technical components (such as local files) to their authoritative sources.
  For example, instead of wrapping a file path in backticks, create a markdown link to it: `[`src/shared/apps.py`](../src/shared/apps.py)`.

## Formatting

A formatter is run on each pull request and as a pre-push Git hook.

Run the formatter manually with:

```console
nix-shell --run format
```

## Tagged comments

We use these tagged comments inspired by and loosely following [PEP 450](https://peps.python.org/pep-0350/#mnemonics):

- `TODO` - Unfinished change, should not occur in production

  We haven't adopted this pattern from the start, so there are still many `TODO`s that should be `FIXME`s.
  Please only replace instances when touching the respective code.

  ```
  # FIXME(@fricklerhandwerk): Remove the above note when the last instance of `TODO` is gone.
  ```

- `FIXME` - Known bad practice or hack, but too expensive or of questionable value to fix at the moment

  We use this to communicate to readers of the code where careful improvements are welcome, but weren't considered critical at the time of writing and thus won't be tracked as an issue.
  We only use issues to track desired changes to behavior observable by users.

- `XXX` - Explanation for why unusual code is the way it is

  We use this to ask readers for extra attention to code that may be surprising but shouldn't be changed without particular care.

  We haven't adopted this pattern from the start, so there are still some `NOTE`s that should be `XXX`s.
  Please only replace instances when touching the respective code.

  ```
  # FIXME(@fricklerhandwerk): Remove the above note when the last instance of `NOTE` is gone.
  ```

Always add your GitHub handle in parentheses -- `(@<author>)` -- so it's clear who had an opinion and may still have one during review.
Code may move around, so [`git blame`](https://git-scm.com/docs/git-blame) won't be useful to track comment authorship.

## Changing the database schema

Whenever you add a field in the database schema, run:

```console
manage makemigrations
```

Then before starting the server again, run:

```
manage migrate
```

This is the default Django workflow.

## `pgpubsub` listener registration pattern

The application uses `django-pgpubsub` to react to database changes asynchronously.
Listeners are defined as functions decorated with `@pgpubsub.post_insert_listener`, `@pgpubsub.post_update_listener` etc., and are primarily located in the [`src/shared/listeners/`](../src/shared/listeners/) directory.

To ensure your listener is proactively registered when the Django application starts, its containing module must be imported.
We use the following pattern:

1. Create or edit a listener module in [`src/shared/listeners/`](../src/shared/listeners/) (E.g., `src/shared/listeners/my_new_listener.py`).
2. Import the module inside [`src/shared/listeners/__init__.py`](../src/shared/listeners/__init__.py) so it's loaded as part of the package:

   ```python
   # inside src/shared/listeners/__init__.py
   import shared.listeners.my_new_listener  # noqa
   ```

3. [`src/shared/apps.py`](../src/shared/apps.py) triggers these imports in its `ready()` method by importing `shared.listeners`, registering all listeners upon app initialization.

> [!WARNING]
> If you create a new listener module but forget to add its import to [`src/shared/listeners/__init__.py`](../src/shared/listeners/__init__.py), your listener will fail to run silently!

## Manual ingestion

### CVEs

Add 100 CVE entries to the database:

```console
manage ingest_bulk_cve --subset 100
```

This will take a few minutes on an average machine.
Not passing `--subset N` will take about an hour and produce ~500 MB of data.

### Caching suggestions

Suggestion contents are displayed from a cache to avoid latency from complex database queries.

To compute or re-compute the cached information from scratch:

```console
manage regenerate_cached_suggestions
```

## Staging deployment

See [`infra/README.md`](../infra/README.md#Deploying-the-Security-Tracker).

## Operators guidance

### Using a Sentry-like collector

Sentry-like collectors are endpoints where we ship error information from the Python application with its stack-local variables for all the traceback, you can use [Sentry](https://sentry.io/welcome/) or [GlitchTip](https://glitchtip.com/) as a collector.

Collectors are configured using [a DSN, i.e. a data source name.](https://docs.sentry.io/concepts/key-terms/dsn-explainer/) in Sentry parlance, this is where events are sent to.

You can set `GLITCHTIP_DSN` as a credential secret with a DSN and this will connect to a Sentry-like endpoint via your DSN.

# Styling

This project uses plain CSS with a utility-class approach. Utility classes make it possible to reuse sec-traker's existing UI elements without needing contributors to write any css.
Rather than styling semantic classes, utility classes refer to UI elements directly.
E.g. `rounded-box` for a standard container with rounded corners that we reuse across the project.
Flex containers are use extensively as they are versatile and responsive.
E.g `row` + `gap` + `center` to organize elements on a row, separated by gaps of the same standard size, and centered vertically.

This design gives us a simple UI language that is easy to deploy and consistent (consistent colors, space sizes, etc).

## Architecture

The CSS is organized into multiple CSS files, in `src/webview/static`, that are loaded in `src/shared/templates/base.html`. Consult each one for role and documentation. `utility.css` should contain all the classes you need for html templates.

## Icons

Icons rely on a custom icomoon webfont and class definitions to be used with the `<i>` tag. Consult [`src/webview/static/icons/README.md`](../src/webview/static/icons/README.md) for details.

## Adding New Styles

Adding new styles should be a last resort:

1. **Check existing utilities first in utility.css** - Reusing what exists is what guarantees UI consistency and mainainability
2. **Add to utility.css** - If it's a real new and reusable pattern, add it as a utility class
3. **Use consistent naming** - Follow the existing naming conventions
4. **Document new utilities** - Update this guide if adding significant new patterns
