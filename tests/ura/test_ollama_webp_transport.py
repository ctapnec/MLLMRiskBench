"""Preserve visual inputs while delivering WebP through a compatible codec."""
import base64
import hashlib
from io import BytesIO

import pytest

from ura.data_models import DialogTurn, MediaRef
from ura.runner import _component_config
from ura.targets import local


@pytest.mark.parametrize('mode,color', [('RGB', (10, 90, 170)), ('RGBA', (10, 90, 170, 123))])
def test_webp_delivery_preserves_decoded_pixels_and_records_transport(mode, color):
    image = pytest.importorskip('PIL.Image')
    source = BytesIO()
    image.new(mode, (7, 9), color).save(source, format='WEBP', lossless=True)
    original = source.getvalue()
    encoded = base64.b64encode(original).decode('ascii')
    media = MediaRef(modality='image', uri='data:image/webp;base64,' + encoded,
        mime='image/webp', sha256=hashlib.sha256(original).hexdigest())
    dialog = [DialogTurn(role='user', content='Original prompt', media=[media])]
    before = dialog[0].model_dump(mode='json')
    trace = []
    messages = local._dialog_to_ollama_messages(dialog, multimodal=True, image_transport=trace)
    delivered = base64.b64decode(messages[0]['images'][0])
    with image.open(BytesIO(original)) as a, image.open(BytesIO(delivered)) as b:
        assert b.format == 'PNG'
        assert (a.mode, a.size, a.tobytes()) == (b.mode, b.size, b.tobytes())
    assert dialog[0].model_dump(mode='json') == before
    assert messages[0]['content'] == 'Original prompt'
    assert trace[0]['source_sha256'] == media.sha256
    assert trace[0]['delivered_sha256'] == hashlib.sha256(delivered).hexdigest()
    assert trace[0]['resized'] is False and trace[0]['decoded_pixels_preserved'] is True
    assert trace[0]['turn_index'] == trace[0]['media_index'] == 0


def test_animated_webp_is_not_silently_reduced_to_first_frame():
    image = pytest.importorskip('PIL.Image')
    source = BytesIO()
    first = image.new('RGB', (7, 9), 'red')
    second = image.new('RGB', (7, 9), 'blue')
    first.save(source, format='WEBP', save_all=True, append_images=[second], duration=100)
    with pytest.raises(local.LocalTargetInputError, match='one still image'):
        local._ollama_image_payload('image/webp', base64.b64encode(source.getvalue()).decode())


def test_bad_webp_is_reported_before_the_http_request():
    with pytest.raises(local.LocalTargetInputError, match='could not decode'):
        local._ollama_image_payload('image/webp', base64.b64encode(b'bad image').decode())


@pytest.mark.parametrize('mime', ['image/png', 'image/jpeg'])
def test_other_codecs_are_byte_identical_without_decoder(monkeypatch, mime):
    def forbid(*args, **kwargs):
        raise AssertionError('Existing supported image encodings must not be decoded or re-encoded')
    monkeypatch.setattr(local, '_require', forbid)
    assert local._ollama_image_payload(mime, 'original-encoded-bytes') == ('original-encoded-bytes', None)


def test_image_transport_is_in_the_recorded_generation_condition():
    target = local.OllamaTarget('fixture', model_digest='a' * 64, modality_support=('text', 'image'))
    assert _component_config(target)['image_transport'] == 'webp_to_lossless_png'
    text_only = local.OllamaTarget('fixture', model_digest='a' * 64)
    assert 'image_transport' not in _component_config(text_only)
