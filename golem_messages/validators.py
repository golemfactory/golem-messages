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


def validate_integer(field_name, value):
    if not isinstance(value, int):
        raise exceptions.FieldError(
            "Should be an integer field",
            field=field_name,
            value=value,
        )


def validate_boolean(field_name, value):
    if not isinstance(value, bool):
        raise exceptions.FieldError(
            f"Should be boolean",
            field=field_name,
            value=value,
        )


def validate_list(field_name, value, min_length, max_length):
    if not (isinstance(value, list) and
            (min_length <= len(value) <= max_length)):
        raise exceptions.FieldError(
            f"Should be a list with minimum {min_length} "
            f"element and maximum {max_length} elements.",
            field=field_name,
            value=value,
        )


def validate_list_of_positive_integers(
        field_name,
        value,
        min_length=1,
        max_length=float('inf')
):
    validate_list(field_name, value, min_length, max_length)
    for element in value:
        if not (isinstance(element, int) and element > 0):
            raise exceptions.FieldError(
                f"Should be an integer greater than 0.0",
                field=field_name,
                value=value
            )


def validate_list_of_non_negative_floats(
        field_name,
        value,
        min_length=1,
        max_length=float('inf')
):
    validate_list(field_name, value, min_length, max_length)
    for element in value:
        if not (isinstance(element, float) and float(element) >= 0.0):
            raise exceptions.FieldError(
                f"Should be a float equal or greater than 0.0",
                field=field_name,
                value=value
            )


def validate_enum(field_name, value, enum_class):
    try:
        enum_class(value)
    except ValueError:
        raise exceptions.FieldError(
            f" Invalid value for enum {enum_class.__name__}",
            field=field_name,
            value=value,
        )


def validate_task_type_with_meta_parameters(
        field_name,
        task_type,
        meta_parameters,
        task_type_meta_parameters,
):
    try:
        task_class = task_type_meta_parameters[task_type]
        task_class(meta_parameters)
    except (exceptions.FieldError, ValueError, KeyError):
        raise exceptions.FieldError(
            f"Given task type: {task_type} is incompatible "
            f"with meta parameters provided: {meta_parameters}.",
            field=field_name,
            value=(task_type, meta_parameters),
        )


def validate_correct_meta_parameters_class(meta_parameters_classes, value):
    if value is None:
        raise exceptions.FieldError(
            'meta_parameters should be an instance one of the'
            f'{meta_parameters_classes} classes',
            field='meta_parameters',
            value=value,
        )
    error_counter = 0
    for script_package in meta_parameters_classes:
        try:
            script_package(value)
        except KeyError:
            error_counter += 1
        if error_counter == len(meta_parameters_classes):
            raise exceptions.FieldError(
                'meta_parameters should be an instance one of '
                f'{meta_parameters_classes} classes',
                field='meta_parameters',
                value=value,
            )
