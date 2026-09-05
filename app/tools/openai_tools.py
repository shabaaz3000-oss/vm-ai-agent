from app.tools.registry import (
    get_llm_visible_tools,
)


# -------------------------------------------------
# EMPTY FUNCTION ARGUMENT SCHEMA
# -------------------------------------------------


EMPTY_ARGUMENT_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
    "additionalProperties": False,
}


# -------------------------------------------------
# BUILD OPENAI TOOL DEFINITIONS
# -------------------------------------------------


def build_openai_tools() -> list[dict]:

    return [
        {
            "type": "function",

            "name":
                tool.name,

            "description":
                tool.description,

            "parameters":
                EMPTY_ARGUMENT_SCHEMA,

            "strict":
                True,
        }

        for tool in
        get_llm_visible_tools()
    ]