from llm_engine import query_llm

if __name__ == "__main__":
    test_prompt = "Explain what is a brute force attack in cybersecurity."
    response = query_llm(test_prompt)
    print("\n[LLM RESPONSE]:\n", response)
