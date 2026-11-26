"""Contract and non-destructive scaffold tests for the portable skill."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'init_project.py'


class SkillContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill = (ROOT / 'SKILL.md').read_text(encoding='utf-8')
        cls.readme = (ROOT / 'README_zh-CN.md').read_text(encoding='utf-8')

    def test_frontmatter_and_entrypoint(self):
        self.assertTrue(self.skill.startswith('---\n'))
        frontmatter = self.skill.split('---', 2)[1]
        self.assertRegex(frontmatter, r'(?m)^name: agent-orchestrator$')
        self.assertRegex(frontmatter, r'(?m)^description: .+')
        self.assertRegex(frontmatter, r'(?m)^  version: "1\.1\.0"$')
        self.assertLess(len(self.skill.splitlines()), 500)

    def test_references_exist(self):
        for link in re.findall(r'`((?:references|assets)/[\w.-]+\.md)`', self.skill):
            self.assertTrue((ROOT / link).is_file(), link)
        for fname in ('AUTONOMY_PROTOCOL.md', 'GRILL_ENGINE.md',
                      'REVIEW_AND_AGENT_PROTOCOL.md', 'SDS_STANDARD.md'):
            self.assertTrue((ROOT / 'references' / fname).exists(), fname)

    def test_autonomy_and_review_contract(self):
        for marker in ('AUTO_FIRST', 'HUMAN_GATE', 'INTERACTIVE_GRILL',
                       'DEFAULT', 'GRILL', 'PLAN_REVIEW', 'SDS_REVIEW',
                       'HANDOFF_READY', 'AUTO_FROZEN', 'HUMAN_APPROVED',
                       'fresh independent task reviewer', 'at most 3',
                       'specific, explicit authorization', 'do not claim'):
            self.assertIn(marker.lower(), self.skill.lower(), marker)
        self.assertIn('AUTO_FIRST + FULL', self.readme)
        self.assertIn('人工批准具体版本', self.readme)
        self.assertIn('需要宿主实际支持', self.readme)

    def test_scaffolder_templates_exist(self):
        for name in ('AUTONOMY', 'STATE', 'PLAN', 'DECISIONS', 'REVIEW_LEDGER',
                     'SDS', 'IMPLEMENTATION_PLAN', 'TASKS', 'HANDOFF'):
            self.assertTrue((ROOT / 'assets' / (name + '_TEMPLATE.md')).exists(), name)

    def test_scaffolder_defaults_to_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = subprocess.run([sys.executable, str(SCRIPT), '--project', tmp],
                               capture_output=True, text=True, check=True)
            self.assertIn('Dry-run only', r.stdout)
            self.assertFalse((Path(tmp) / 'docs' / 'agent-orchestrator').exists())

    def test_scaffolder_creates_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = [sys.executable, str(SCRIPT), '--project', tmp, '--apply']
            subprocess.run(command, capture_output=True, text=True, check=True)
            dest = Path(tmp) / 'docs' / 'agent-orchestrator'
            self.assertEqual(len(list(dest.glob('*.md'))), 9)
            policy = dest / 'AUTONOMY.md'
            self.assertIn('AUTO_FIRST', policy.read_text(encoding='utf-8'))
            policy.write_text('CUSTOM POLICY\n', encoding='utf-8')
            again = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertIn('SKIP existing', again.stdout)
            self.assertEqual(policy.read_text(encoding='utf-8'), 'CUSTOM POLICY\n')

    def test_scaffolder_rejects_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = [sys.executable, str(SCRIPT), '--project', tmp,
                       '--destination', '../escape', '--apply']
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(tmp).parent / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
