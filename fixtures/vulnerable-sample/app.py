import os
import pickle

# Intentionally vulnerable sample for scanner demos — do not deploy.
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def run_user_code(user_input: str) -> None:
    eval(user_input)  # noqa: S307


def load_state(data: bytes) -> object:
    return pickle.loads(data)  # noqa: S301


def sql_query(user_id: str) -> str:
    return f"SELECT * FROM users WHERE id = '{user_id}'"


def main() -> None:
    token = os.environ.get("TOKEN", "hardcoded-dev-token-12345")
    print(token)


if __name__ == "__main__":
    main()
