"""Model choice and local credential persistence; no paid API calls."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from traffic_agent.config import Config, MODEL_PRESETS, choose_model, provider_for
from traffic_agent.credentials import Credentials, active_key


class ModelSettingsTests(unittest.TestCase):
    def test_legacy_output_and_call_limits_are_ignored_and_not_saved_again(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'config.local.json'
            path.write_text(json.dumps({'max_output_tokens': 1500, 'max_calls': 73}), encoding='utf-8')
            config = Config.load(path)
            self.assertFalse(hasattr(config, 'max_output_tokens'))
            self.assertFalse(hasattr(config, 'max_calls'))
            config.save(path)
            self.assertNotIn('max_output_tokens', json.loads(path.read_text(encoding='utf-8')))
            self.assertNotIn('max_calls', json.loads(path.read_text(encoding='utf-8')))

    def test_provider_model_choices_set_endpoint_and_peak_prices(self):
        for provider, preset in MODEL_PRESETS.items():
            for model, prices in preset['models'].items():
                config = choose_model(Config(), provider, model)
                self.assertEqual(config.base_url, preset['base_url'])
                self.assertEqual((config.input_price, config.output_price), prices)
                self.assertEqual(provider_for(config), provider)
        with self.assertRaises(ValueError):
            choose_model(Config(), 'DeepSeek', 'gpt-4o-mini')

    def test_saved_selection_beats_old_environment_override(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'config.local.json'
            choose_model(Config(), 'OpenAI', 'gpt-4.1-mini').save(path)
            with patch.dict(os.environ, {'LLM_BASE_URL': 'https://api.deepseek.com', 'LLM_MODEL': 'deepseek-flash'}):
                config = Config.load(path)
            self.assertEqual((provider_for(config), config.model), ('OpenAI', 'gpt-4.1-mini'))

    def test_legacy_deepseek_selection_migrates_to_flash(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'config.local.json'
            path.write_text(json.dumps({'base_url': 'https://api.deepseek.com/v1', 'model': 'deepseek-chat',
                                        'input_price': 0, 'output_price': 0}), encoding='utf-8')
            config = Config.load(path)
            self.assertEqual(config.model, 'deepseek-flash')
            config.validate()

    @unittest.skipUnless(os.name == 'nt', 'Windows DPAPI required')
    def test_keys_are_separate_encrypted_and_reloadable(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            vault = Credentials(Path(directory) / 'credentials.local.json')
            vault.save('DeepSeek', 'sample-deepseek-secret')
            vault.save('OpenAI', 'sample-openai-secret')
            self.assertEqual(vault.get('DeepSeek'), 'sample-deepseek-secret')
            self.assertEqual(vault.get('OpenAI'), 'sample-openai-secret')
            self.assertNotIn('sample-', vault.path.read_text(encoding='utf-8'))
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'environment-key'}):
                self.assertEqual(active_key(vault, 'OpenAI'), 'sample-openai-secret')
                self.assertEqual(active_key(vault, 'DeepSeek'), 'sample-deepseek-secret')


if __name__ == '__main__':
    unittest.main()
