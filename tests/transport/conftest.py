import pytest

import helpers


@pytest.fixture
def pair(tmp_path):
    pair = helpers.make_pair(tmp_path)
    yield pair
    helpers.close_pair(pair)
