def flatten_json(data, prefix=''):
    result = {}
    for key, value in data.items():
        new_key = prefix + key if prefix else key
        if isinstance(value, dict):
            result.update(flatten_json(value, new_key + '.'))
        else:
            result[new_key] = value
    return result