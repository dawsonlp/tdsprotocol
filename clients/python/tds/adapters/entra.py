"""Entra ID logins through azure-identity (D-55): any of its credentials, sync or async.

    from azure.identity import DefaultAzureCredential
    credential = DefaultAzureCredential()
    tds.connect(host, port, login=tds.EntraToken(token(credential)))         # a token in advance
    tds.connect(host, port, login=tds.EntraLogin(fetch(credential)))         # fetched mid-login
"""

RESOURCE = "https://database.windows.net/"


def _scope(resource: str) -> str:
    return resource.rstrip("/") + "/.default"


async def _token(credential, scope: str) -> str:
    result = credential.get_token(scope)
    if hasattr(result, "__await__"):
        result = await result
    return result.token


def token(credential, resource: str = RESOURCE):
    """For EntraToken: a function that gives a token for Azure SQL, each time a connection logs in."""
    return lambda: _token(credential, _scope(resource))


def fetch(credential):
    """For EntraLogin: a function that gives a token for the resource the server names (its SPN)."""
    return lambda spn, sts_url: _token(credential, _scope(spn))
