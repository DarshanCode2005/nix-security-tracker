# Onboarding and Local Setup

## Setting up credentials

The service connects to GitHub on startup, in order to manage permissions according to GitHub team membership in the configured organisation.

<details><summary>Create a Django secret key</summary>

```console
python3 -c 'import secrets; print(secrets.token_hex(100))' > .credentials/SECRET_KEY
```

</details>

<details><summary>Set up GitHub authentication</summary>

1.  Create a new or select an existing GitHub organisation to associate with the Nixpkgs security tracker.

    We're using <https://github.com/Nix-Security-WG> for development.
    - In the **Settings** tab under **Personal access tokens**, ensure that personal access tokens are allowed.
    - In the **Teams** tab, ensure there are at two teams for mapping user permissions.
      They will correspond to [`nixpkgs-committers`](https://github.com/orgs/nixos/teams/nixpkgs-committers) and [`security`](https://github.com/orgs/nixos/teams/security).
    - In the **Repositories** tab, ensure there's a repository for posting issues.
      It will correspond to [`nixpkgs`](https://github.com/nixos/nixpkgs).
      In the **Settings** tab on that repository, in the **Features** section, ensure that _Issues_ are enabled.

2.  In the GitHub organisation settings configure the GitHub App

    We're using <https://github.com/apps/sectracker-testing> for local development and <https://github.com/apps/sectracker-demo> for the public demo deployment.
    [Register a new GitHub application](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app) if needed.
    - In **Personal access tokens** approve the request under **Pending requests** if approval is required
    - In **GitHub Apps**, go to **Configure** and then **App settings** (top row). Under **Permissions & events** (side panel):
      - In **Repository Permissions** select **Administration (read-only)**, **Issues (read and write)**, and **(Metadata: read-only)**.
      - In **Organization Permissions** select **Administration (read-only)** and **(Members: read-only)**.

      Store the **Client ID** in `.credentials/GH_CLIENT_ID`

    - In the application settings / **General** / **Generate a new client secret**

      Store the value in `.credentials/GH_SECRET`

    - In the application settings / **General** / **Private keys** / **Generate a private key**

      Store the value in `.credentials/GH_APP_PRIVATE_KEY`

    - In the application settings / **Install App**

      Make sure the app is installed in the correct organisation's account.

      <details><summary>If the account that shows up is your Developer Account</summary>

      In the application settings / **Advanced**
      - **Transfer ownership of this GitHub App** to the organisation account.

      </details>

    - In organisation settings under **GitHub Apps** / **Installed GitHub Apps** / **<GH_APP_NAME>** / **Configure** page

      Check the URL, which has the pattern `https://github.com/organizations/<ORG_NAME>/settings/installations/<INSTALLATION_ID>`.

      Store the value **<INSTALLATION_ID>** in `.credentials/GH_APP_INSTALLATION_ID`.

</details>

<details><summary>Set up Github App webhooks</summary>

For now, we require a GitHub webhook to receive push notifications when team memberships change.
To configure the GitHub app and the webhook in the GitHub organisation settings:

- In **Code, planning, and automation** Webhooks, create a new webhook:
  - In **Payload URL**, input "https://<APP_DOMAIN>/github-webhook".
  - In **Content Type** choose **application/json**.
  - Generate a token and put in **Secret**. This token should be in `./credentials/GH_WEBHOOK_SECRET`.
  - Choose **Let me select individual events**
    - Deselect **Pushes**.
    - Select **Memberships**.

</details>

## Running the service in a development environment

Start a development shell:

```console
nix-shell
```

Or set up [`nix-direnv`](https://github.com/nix-community/nix-direnv) on your system and run `direnv allow` to enter the development environment automatically when entering the project directory.

### Set up a local database

Currently only [PostgreSQL](https://www.postgresql.org/) is supported as a database.
Assuming you have a local checkout of this repository at `~/src/nix-security-tracker`, in your NixOS configuration, add the following entry to `imports` and rebuild your system:

```nix
{ ... }:
{
  imports = [
    (import ~/src/nix-security-tracker { }).dev-setup
  ];

  nix-security-tracker-dev-environment = {
    enable = true;
    # The user you run the backend application as, so that you can access the local database
    user = "myuser";
  };
}
```

### Start the service

The service is comprised of the Django server and workers for ingesting CVEs and derivations.
What needs to be run is defined in the [`Procfile`](../Procfile) managed by [hivemind](https://github.com/DarthSim/hivemind).

Run everything with:

```bash
hivemind
```

### Resetting the database

In order to start over you need SSH [access to the staging environment](../infra/README.md#adding-ssh-keys).
Tools for the following are available in the development shell.
Delete the database and recreate it, then restore it from a dump, and (just in case the dump is behind the code) run migrations:

```bash
dropdb nix-security-tracker
ssh root@tracker-staging.security.nixos.org "sudo -u postgres pg_dump --create nix-security-tracker | zstd" | zstdcat | pv | psql
manage migrate
```

## Running the service in a container

On NixOS, you can run the service in a [`systemd-nspawn` container](https://search.nixos.org/options?show=containers) to preview a deployment.

Assuming you have a local checkout of this repository at `~/src/nix-security-tracker`, in your NixOS configuration, add the following entry to `imports` and rebuild your system:

```nix
{ ... }:
{
  imports = [
    (import ~/src/nix-security-tracker { }).dev-container
    # ...
   ];
}
```

The service will be accessible at <http://172.31.100.1>.

## Running tests

Run integration tests:

```console
nix-build -A tests
```

Interact with the involved virtual machines in a test:

```
$(nix-build -A tests.driverInteractive)/bin/nixos-test-driver
```
