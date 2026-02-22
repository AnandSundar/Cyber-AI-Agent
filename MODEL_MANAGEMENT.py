"""
Module for managing AI model selection, cost estimation, and rate limit assessment.
"""

from colorama import Fore, Style
import tiktoken
import guardrails

# ---- Settings ---------------------------------------------------------------

# https://platform.openai.com/settings/organization/limits
CURRENT_TIER = "1"  # Valid: "free", "1", "2", "3", "4", "5"
DEFAULT_MODEL = "gpt-5-mini"
WARNING_RATIO = 0.80  # 80%


def money(usd):
    """Formats a float value as a currency string (USD)."""
    return f"${usd:.6f}" if usd < 0.01 else f"${usd:.2f}"


def color_for_usage(used, limit):
    """
    Determine the Fore color code based on how much of the limit has been consumed.
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
    Return a color-coded string representing usage against a limit.
    """
    col = color_for_usage(used, limit)
    lim = "∞" if limit is None else str(limit)
    return f"{label}: {col}{used}/{lim}{Style.RESET_ALL}"


def estimate_cost(input_tokens, output_tokens, model_info):
    """
    Estimate the total cost of a request based on token counts and model pricing.
    """
    cin = input_tokens * model_info["cost_per_million_input"] / 1_000_000.0
    cout = output_tokens * model_info["cost_per_million_output"] / 1_000_000.0
    return cin + cout


def print_model_table(input_tokens, current_model, tier, assumed_output_tokens=500):
    """
    Print a comparison table of available models, their limits, and estimated costs.
    """
    print(f"Model limits and estimated total cost:{Fore.WHITE}\n")
    for name, info in guardrails.ALLOWED_MODELS.items():
        tier_data = info.get("tier", {})
        tpm_limit = tier_data.get(tier) if isinstance(tier_data, dict) else None
        usage_text = colorize("input limit", input_tokens, info["max_input_tokens"])
        tpm_text = colorize("rate_limit", input_tokens, tpm_limit)
        est = estimate_cost(input_tokens, assumed_output_tokens, info)
        tag = f"{Fore.CYAN} <-- (current){Fore.WHITE}" if name == current_model else ""
        print(
            f"{name:<12} | {usage_text:<35} | {tpm_text:<32} | out_max: {info['max_output_tokens']:<6} | est_cost: {money(est)}{tag}"
        )
    print("")


def assess_limits(model_name, input_tokens, tier):
    """
    Evaluate if the current input tokens exceed the hard limits or tier-based TPM limits.
    """
    info = guardrails.ALLOWED_MODELS[model_name]
    msgs = []

    # Input cap
    max_input_tokens = info.get("max_input_tokens", 0)
    # Ensure max_input_tokens is treated as a number (int/float), not a dict
    if not isinstance(max_input_tokens, (int, float)):
        max_input_tokens = 0
    usage_txt = colorize("input limit", input_tokens, max_input_tokens)
    if input_tokens > max_input_tokens:
        msgs.append(f"🚨 ERROR: {usage_txt} exceeds the input limit for {model_name}.")
    elif input_tokens >= WARNING_RATIO * max_input_tokens:
        msgs.append(
            f"⚠️ WARNING: {usage_txt} is at least 80% of the input limit for {model_name}."
        )
    else:
        msgs.append(f"✅ Safe: {usage_txt} is within the input limit for {model_name}.")

    # TPM cap
    tier_data = info.get("tier", {})
    tpm_limit = tier_data.get(tier) if isinstance(tier_data, dict) else None
    # Ensure tpm_limit is a valid number (int or float), not None or a dict
    if tpm_limit is not None and not isinstance(tpm_limit, (int, float)):
        tpm_limit = None
    tpm_txt = colorize("rate_limit", input_tokens, tpm_limit)
    if tpm_limit is not None and isinstance(tpm_limit, (int, float)):
        if input_tokens > tpm_limit:
            msgs.append(
                f"⚠️ WARNING: {tpm_txt} exceeds the TPM rate limit for {model_name} ({tpm_limit}) — may be too large."
            )
        elif input_tokens >= WARNING_RATIO * tpm_limit:
            msgs.append(
                f"⚠️ WARNING: {tpm_txt} is at least 80% of the TPM rate limit for {model_name}."
            )
        else:
            msgs.append(
                f"✅ Safe: {tpm_txt} is within the TPM rate limit for {model_name}."
            )
    else:
        msgs.append(f"ℹ️ No TPM tier limit known for {model_name} at tier '{tier}'.")

    if input_tokens > max_input_tokens or (
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
    High-level flow to select a model and verify it can handle the current token load.
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
        prompt = f"{Fore.WHITE}Continue with '{model_name}'? (Enter to continue / type a model name / 'list'):{Fore.WHITE} "
        choice = input(prompt).strip()

        if choice == "" or choice.lower() in {"y", "yes", "continue", "c"}:
            info = guardrails.ALLOWED_MODELS[model_name]
            tier_data = info.get("tier", {})
            tpm_limit = tier_data.get(tier) if isinstance(tier_data, dict) else None
            over_input = input_tokens > info["max_input_tokens"]
            over_tpm = (tpm_limit is not None) and (input_tokens > tpm_limit)

            if over_input or over_tpm:
                msg = "input limit" if over_input else "TPM rate limit"
                print(
                    f"{Fore.YELLOW}⚠️ WARNING: input may exceed {model_name}'s {msg}.\n{Fore.WHITE}"
                )
                # continue
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
            "Press Enter to continue, type a valid model name, or 'list' to see options."
        )


def count_tokens(messages, model):
    """
    Cheap estimate for chat messages.
    """
    try:
        enc = tiktoken.encoding_for_model(model)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")

    text = ""
    for m in messages:
        text += m.get("role", "") + " " + m.get("content", "") + "\n"
    return len(enc.encode(text))
