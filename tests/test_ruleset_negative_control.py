def test_ruleset_negative_control():
    """
    Intentional CI failure used only to prove that
    protected-main rules prevent merging failed code.
    """

    assert False, (
        "Intentional Step 43 negative-control failure"
    )
