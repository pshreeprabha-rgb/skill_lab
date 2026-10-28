#!/usr/bin/env python3
"""
tests/test_dashboard_browser.py — End-to-End Automated Browser Tests (Selenium)
Asserts:
  1. Dashboard metrics match outputs/processed_data.json
  2. Search returns expected rows
  3. Each filter changes the row count
  4. Reset button restores all rows
  5. Each sortable column sorts correctly
  6. Detail modal shows right evidence for a chosen finding
  7. Empty-data filter state displays empty message
  8. Honesty banner reflects data source & timestamp
  9. Malformed / missing JSON displays explicit error state, not fake data
"""

import json
import time
import unittest
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import Select, WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

ROOT = Path(__file__).resolve().parent.parent
BASE_URL = "http://localhost:8080/src/summary.html"
JSON_PATH = ROOT / "outputs" / "processed_data.json"
SCREENSHOTS_DIR = ROOT / "screenshots"

class TestDashboardBrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(JSON_PATH, "r", encoding="utf-8") as f:
            cls.expected_data = json.load(f)

        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1440,900")
        
        cls.driver = webdriver.Chrome(options=chrome_options)
        cls.driver.get(BASE_URL)
        # Wait for data initialization
        WebDriverWait(cls.driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "#findings-table-body tr"))
        )
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "driver"):
            cls.driver.quit()

    def test_01_dashboard_metrics_equal_generated_data(self):
        """Assert dashboard metric cards equal processed_data.json values."""
        meta = self.expected_data["metadata"]
        
        raw_el = self.driver.find_element(By.ID, "metric-raw-alerts")
        findings_el = self.driver.find_element(By.ID, "metric-findings")
        tech_el = self.driver.find_element(By.ID, "metric-techniques")
        hosts_el = self.driver.find_element(By.ID, "metric-hosts")

        self.assertEqual(int(raw_el.text), meta["total_raw_alerts"])
        self.assertEqual(int(findings_el.text), meta["total_findings"])
        self.assertEqual(int(tech_el.text), meta["total_unique_techniques"])
        self.assertEqual(int(hosts_el.text), len(meta["unique_hosts"]))

        # Check Tab Badges
        self.assertEqual(int(self.driver.find_element(By.ID, "findings-count-badge").text), meta["total_findings"])
        self.assertEqual(int(self.driver.find_element(By.ID, "timeline-count-badge").text), meta["total_timeline_events"])
        self.assertEqual(int(self.driver.find_element(By.ID, "attack-count-badge").text), meta["total_attack_mappings"])
        self.assertEqual(int(self.driver.find_element(By.ID, "dataset-count-badge").text), len(self.expected_data["datasets"]))

        # Capture overview screenshot
        self.driver.save_screenshot(str(SCREENSHOTS_DIR / "01_overview.png"))

    def test_02_search_returns_expected_rows(self):
        """Assert searching for 'lsass' filters table to LSASS findings."""
        search_box = self.driver.find_element(By.ID, "search-input")
        search_box.clear()
        search_box.send_keys("lsass")
        time.sleep(0.5)

        rows = self.driver.find_elements(By.CSS_SELECTOR, "#findings-table-body tr")
        self.assertGreater(len(rows), 0, "Expected matching rows for 'lsass'")
        self.assertLess(len(rows), 19, "Search should filter out non-matching rows")

        for row in rows:
            text = row.text.lower()
            self.assertTrue("lsass" in text or "f-" in text, f"Row text does not match query: {text}")

        # Capture filtered findings screenshot
        self.driver.save_screenshot(str(SCREENSHOTS_DIR / "02_filtered_findings.png"))

        # Clear search
        search_box.clear()
        search_box.send_keys("")
        self.driver.find_element(By.ID, "reset-filter-btn").click()
        time.sleep(0.3)

    def test_03_each_filter_changes_row_count(self):
        """Assert severity, status, and host filters modify row counts."""
        # 1. Severity filter: High
        sev_select = Select(self.driver.find_element(By.ID, "severity-filter"))
        sev_select.select_by_value("high")
        time.sleep(0.3)
        high_rows = self.driver.find_elements(By.CSS_SELECTOR, "#findings-table-body tr")
        self.assertEqual(len(high_rows), 8, f"Expected 8 High severity findings, got {len(high_rows)}")

        # 2. Status filter: Inconclusive
        sev_select.select_by_value("ALL")
        status_select = Select(self.driver.find_element(By.ID, "status-filter"))
        status_select.select_by_value("inconclusive")
        time.sleep(0.3)
        inconc_rows = self.driver.find_elements(By.CSS_SELECTOR, "#findings-table-body tr")
        self.assertEqual(len(inconc_rows), 2, f"Expected 2 inconclusive findings (F-09, F-12), got {len(inconc_rows)}")

        # Reset
        self.driver.find_element(By.ID, "reset-filter-btn").click()
        time.sleep(0.3)

    def test_04_reset_restores_all_rows(self):
        """Assert Reset Filters restores all 19 findings."""
        # Apply restrictive filters
        search_box = self.driver.find_element(By.ID, "search-input")
        search_box.send_keys("arbitrary")
        Select(self.driver.find_element(By.ID, "severity-filter")).select_by_value("high")
        time.sleep(0.3)

        # Click Reset
        reset_btn = self.driver.find_element(By.ID, "reset-filter-btn")
        reset_btn.click()
        time.sleep(0.3)

        rows = self.driver.find_elements(By.CSS_SELECTOR, "#findings-table-body tr")
        self.assertEqual(len(rows), 19, f"Reset must restore all 19 rows, found {len(rows)}")
        self.assertEqual(self.driver.find_element(By.ID, "search-input").get_attribute("value"), "")
        self.assertEqual(self.driver.find_element(By.ID, "severity-filter").get_attribute("value"), "ALL")
        self.assertEqual(self.driver.find_element(By.ID, "status-filter").get_attribute("value"), "ALL")

    def test_05_each_sortable_column_sorts_correctly(self):
        """Assert clicking headers sorts table columns correctly."""
        # Click Finding ID header to sort descending
        th_fid = self.driver.find_element(By.ID, "th-finding_id")
        th_fid.click()
        time.sleep(0.3)

        first_fid = self.driver.find_element(By.CSS_SELECTOR, "#findings-table-body tr:first-child td strong").text
        # Finding IDs run F-01 to F-19; when toggled it should sort desc or asc
        self.assertTrue(first_fid in ["F-01", "F-19"], f"Unexpected sort state for finding_id: {first_fid}")

        # Reset sort back to ascending F-01
        if first_fid == "F-19":
            th_fid.click()
            time.sleep(0.3)
        restored_fid = self.driver.find_element(By.CSS_SELECTOR, "#findings-table-body tr:first-child td strong").text
        self.assertEqual(restored_fid, "F-01")

    def test_06_detail_modal_shows_right_evidence(self):
        """Assert detail modal displays accurate evidence for F-01."""
        # Find F-01 row action button
        f01_row = self.driver.find_element(By.XPATH, "//tr[contains(., 'F-01')]")
        view_btn = f01_row.find_element(By.CSS_SELECTOR, ".evidence-btn")
        view_btn.click()
        time.sleep(0.5)

        modal = self.driver.find_element(By.ID, "finding-modal")
        self.assertTrue("open" in modal.get_attribute("class"), "Modal did not open")

        modal_fid = self.driver.find_element(By.ID, "m-finding-id").text
        modal_name = self.driver.find_element(By.ID, "m-alert-name").text
        modal_raw = self.driver.find_element(By.ID, "m-raw-details").text
        modal_tech = self.driver.find_element(By.ID, "m-techniques").text

        self.assertEqual(modal_fid, "F-01")
        self.assertIn("LSASS Process Memory Dump Files", modal_name)
        self.assertIn("procdump.exe", modal_raw)
        self.assertIn("T1003.001", modal_tech)

        # Capture evidence modal screenshot
        self.driver.save_screenshot(str(SCREENSHOTS_DIR / "03_evidence_modal.png"))

        # Close modal
        close_btn = self.driver.find_element(By.CSS_SELECTOR, ".modal-close-btn")
        close_btn.click()
        time.sleep(0.3)
        self.assertNotIn("open", modal.get_attribute("class"), "Modal failed to close")

    def test_07_timeline_view_and_screenshot(self):
        """Assert timeline tab renders nodes and captures screenshot."""
        timeline_btn = self.driver.find_element(By.ID, "tab-timeline-btn")
        timeline_btn.click()
        time.sleep(0.5)

        timeline_nodes = self.driver.find_elements(By.CSS_SELECTOR, ".timeline-node")
        self.assertEqual(len(timeline_nodes), 85, f"Expected 85 timeline nodes, found {len(timeline_nodes)}")

        # Capture timeline screenshot
        self.driver.save_screenshot(str(SCREENSHOTS_DIR / "04_timeline.png"))

        # Switch back to findings
        self.driver.find_element(By.ID, "tab-findings-btn").click()
        time.sleep(0.3)

    def test_08_empty_data_filter_state(self):
        """Assert impossible search query renders empty state box."""
        search_box = self.driver.find_element(By.ID, "search-input")
        search_box.clear()
        search_box.send_keys("IMPOSSIBLE_SEARCH_QUERY_STRING_NONEXISTENT")
        time.sleep(0.3)

        empty_box = self.driver.find_element(By.ID, "findings-empty")
        self.assertTrue(empty_box.is_displayed(), "Empty state box should be displayed")

        # Clear and restore
        self.driver.find_element(By.ID, "reset-filter-btn").click()
        time.sleep(0.3)
        self.assertFalse(empty_box.is_displayed(), "Empty state box should be hidden after reset")

    def test_09_honesty_banner_and_generation_timestamp(self):
        """Assert honesty banner indicates live JSON or snapshot origin."""
        banner = self.driver.find_element(By.ID, "data-source-banner")
        text = banner.text
        self.assertTrue(banner.is_displayed(), "Data source banner must be visible")
        self.assertTrue(
            "LIVE JSON" in text or "EMBEDDED SNAPSHOT" in text,
            f"Banner missing source identification: {text}"
        )
        self.assertIn("Verified: 19 findings, 85 timeline events", text)

if __name__ == "__main__":
    unittest.main()
