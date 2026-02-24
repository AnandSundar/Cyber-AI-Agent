"""Model management module for OpenAI model selection and token counting.

This module provides utilities for managing OpenAI model selection, tracking
token usage limits, estimating costs, and interactive model selection.
"""

from colorama import Fore, Style
import tiktoken
import guardrails

# ---- Settings ---------------------------------------------------------------

# https://platform.openai.com/settings/organization/limits
CURRENT_TIER = "4"  # "free", "1", "2", "3", "4", "5"
DEFAULT_MODEL = "gpt-5-mini"
WARNING_RATIO = 0.80  # 80%


def money(usd):
    """
    Format a USD amount as a string with appropriate precision.

    Args:
        usd (float): The amount in USD.

    Returns:
        str: Formatted dollar string with 6 decimals for small amounts,
             2 decimals otherwise.
    """
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"


def color_for_usage(used, limit):
    """
    Determine the appropriate color based on usage relative to limit.

    Args:
        used (int): The amount used.
        limit (int or None): The limit, or None for unlimited.

    Returns:
        str: The colorama color code to use.
    """
    if limit is None:
        return Fore.LIGHTGREEN_EX
    if used > limit:
        return Fore.LIGHTRED_EX
    if used >= WARNING_RATIO * limit:
        return Fore.LIGHTYELLOW_EX
    return Fore.LIGHTGREEN_EX


def colorize(label, used, limit):
    """
    Create a colored usage string showing used/limit.

    Args:
        label (str): The label for the usage metric.
        used (int): The amount used.
        limit (int or None): The limit, or None for unlimited.

    Returns:
        str: Formatted and colored usage string.
    """
    col = color_for_usage(used, limit)
    lim = "∞" if limit is None else str(limit)
    return f"{label}: {col}{used}/{lim}{Style.RESET_ALL}"


def estimate_cost(input_tokens, output_tokens, model_info):
    """
    Estimate the cost for a given number of input and output tokens.

    Args:
        input_tokens (int): Number of input tokens.
        output_tokens (int): Number of output tokens.
        model_info (dict): Model information containing cost per million.

    Returns:
        float: Estimated cost in USD.
    """
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout


def print_model_table(input_tokens, current_model, tier, assumed_output_tokens=500):
    """
    Print a table of all models with their limits and estimated costs.

    Args:
        input_tokens (int): Number of input tokens to estimate for.
        current_model (str): The currently selected model name.
        tier (str): The current usage tier.
        assumed_output_tokens (int): Assumed output tokens for cost estimate.
    """
    print(f"Model limits and estimated total cost:{Fore.WHITE}\n")
    for name, info in guardrails.ALLOWED_MODELS.items():
        tpm_limit = info["tier"].get(tier)
        usage_text = colorize("input limit", input_tokens, info["max_input_tokens"])
        tpm_text = colorize("rate_limit", input_tokens, tpm_limit)
        est = estimate_cost(input_tokens, assumed_output_tokens, info)
        tag = f"{Fore.CYAN} <-- (current){Fore.WHITE}" if name == current_model else ""
        print(
            f"{name:<12} | {usage_text:<35} | {tpm_text:<32} | "
            f"out_max: {info['max_output_tokens']:<6} | "
            f"est_cost: {money(est)}{tag}"
        )
    print("")


def assess_limits(model_name, input_tokens, tier):
    """
    Assess and print warnings about token limits for a model.

    Args:
        model_name (str): The model name to assess.
        input_tokens (int): Number of input tokens.
        tier (str): The current usage tier.
    """
    info = guardrails.ALLOWED_MODELS[model_name]
    msgs = []

    # Input cap
    usage_txt = colorize("input limit", input_tokens, info["max_input_tokens"])
    if input_tokens > info["max_input_tokens"]:
        msgs.append(f"🚨 ERROR: {usage_txt} exceeds the input limit for {model_name}.")
    elif input_tokens >= WARNING_RATIO * info["max_input_tokens"]:
        msgs.append(
            f"⚠️ WARNING: {usage_txt} is at least 80% of the input limit "
            f"for {model_name}."
        )
    else:
        msgs.append(f"✅ Safe: {usage_txt} is within the input limit for {model_name}.")

    # TPM cap
    tpm_limit = info["tier"].get(tier)
    tpm_txt = colorize("rate_limit", input_tokens, tpm_limit)
    if tpm_limit is not None:
        if input_tokens > tpm_limit:
            msgs.append(
                f"⚠️ WARNING: {tpm_txt} exceeds the TPM rate limit for "
                f"{model_name} ({tpm_limit}) — may be too large."
            )
        elif input_tokens >= WARNING_RATIO * tpm_limit:
            msgs.append(
                f"⚠️ WARNING: {tpm_txt} is at least 80% of the TPM rate "
                f"limit for {model_name}."
            )
        else:
            msgs.append(
                f"✅ Safe: {tpm_txt} is within the TPM rate limit for {model_name}."
            )
    else:
        msgs.append(f"ℹ️ No TPM tier limit known for {model_name} at tier '{tier}'.")

    if input_tokens > info["max_input_tokens"] or (
        tpm_limit is not None and input_tokens > tpm_limit
    ):
        msgs += [
            "",
            "Try these to make it smaller:",
            " - Focus on one user or device",
            " - Use a shorter time range",
            " - Remove extra context you don't need",
        ]

    print("\n".join(msgs))
    print("")


def choose_model(
    model_name,
    input_tokens,
    tier=CURRENT_TIER,
    assumed_output_tokens=500,
    interactive=True,
):
    """
    Interactively select an OpenAI model with limit checking.

    Args:
        model_name (str): The initial model name to use.
        input_tokens (int): Number of input tokens.
        tier (str): The current usage tier.
        assumed_output_tokens (int): Assumed output tokens for cost estimate.
        interactive (bool): Whether to prompt for user input.

    Returns:
        str: The selected model name.
    """
    if model_name not in guardrails.ALLOWED_MODELS:
        print(
            Fore.LIGHTRED_EX
            + f"Unknown model '{model_name}'. Defaulting to {DEFAULT_MODEL}."
            + Style.RESET_ALL
            + Fore.RESET
        )
        model_name = DEFAULT_MODEL

    print_model_table(input_tokens, model_name, tier, assumed_output_tokens)
    assess_limits(model_name, input_tokens, tier)

    if not interactive:
        return model_name

    while True:
        prompt = (
            f"{Fore.WHITE}Continue with '{model_name}'? "
            f"(Enter to continue / type a model name / 'list'):{Fore.WHITE} "
        )
        choice = input(prompt).strip()

        if choice == "" or choice.lower() in {"y", "yes", "continue", "c"}:
            info = guardrails.ALLOWED_MODELS[model_name]
            tpm_limit = info["tier"].get(tier)
            over_input = input_tokens > info["max_input_tokens"]
            over_tpm = (tpm_limit is not None) and (input_tokens > tpm_limit)

            if over_input or over_tpm:
                msg = "input limit" if over_input else "TPM rate limit"
                print(
                    f"{Fore.YELLOW}⚠️ WARNING: input may exceed "
                    f"{model_name}'s {msg}.\n{Fore.WHITE}"
                )
            return model_name

        if choice.lower() in {"list", "models"}:
            print("\nAvailable models: " + ", ".join(guardrails.ALLOWED_MODELS.keys()))
            continue

        if choice in guardrails.ALLOWED_MODELS:
            model_name = choice
            info = guardrails.ALLOWED_MODELS[model_name]
            print("")
            print(f"Switched to model: '{model_name}'.\n")

            # NEW: immediately check & warn for the newly selected model, incl. TPM
            assess_limits(model_name, input_tokens, tier)
            est = estimate_cost(input_tokens, assumed_output_tokens, info)
            print(f"estimated total cost: {money(est)}\n")
            continue

        print(
            "Press Enter to continue, type a valid model name, "
            "or 'list' to see options."
        )


def count_tokens(messages, model):
    """
    Estimate the token count for a list of chat messages.

    Uses tiktoken to count tokens, falling back to cl100k_base encoding
    if the model is not recognized.

    Args:
        messages (list): List of message dictionaries with 'role' and 'content'.
        model (str): The model name to use for tokenization.

    Returns:
        int: The estimated token count.
    """
    try:
        enc = tiktoken.encoding_for_model(model)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")

    text = ""
    for m in messages:
        text += m.get("role", "") + " " + m.get("content", "") + "\n"
    return len(enc.encode(text))
