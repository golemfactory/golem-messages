import functools

import semantic_version

from golem_messages import exceptions


def validate_varchar(field_name, value, max_length):
    if not (isinstance(value, str) and len(value) <= max_length):
        raise exceptions.FieldError(
            "Should be a string of length <= {max_length}".format(
                max_length=max_length,
            ),
            field=field_name,
            value=value,
        )


validate_varchar128 = functools.partial(
    validate_varchar,
    max_length=128,
)


def validate_integer(field_name, value):
    if not isinstance(value, int):
        raise exceptions.FieldError(
            "Should be an integer",
            field=field_name,
            value=value,
        )


def validate_boolean(field_name, value):
    if not isinstance(value, bool):
        raise exceptions.FieldError(
            "Should be a boolean",
            field=field_name,
            value=value,
        )


def validate_version(field_name, value):
    try:
        semantic_version.Version(value)
    except (TypeError, ValueError) as e:
        raise exceptions.FieldError(
            "Should be a version",
            field=field_name,
            value=value,
        ) from e


def validate_dict(field_name, value):
    if not isinstance(value, dict):
        raise exceptions.FieldError(
            "dict is expected not {}".format(
                type(value),
            ),
            field=field_name,
            value=value,
        )
