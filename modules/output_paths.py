# modules/output_paths.py
"""
Automated PCAP Forensic Analysis Tool - Çıktı dizini çözümleme.

Bir capture'ın ürettiği TÜM adli çıktılar (HTML raporu, JSON/CSV/PDF
export'ları) aynı klasörde toplanmalıdır; analist tek bir capture'ın
delillerini tek yerde bulmalıdır. Kural bu yüzden tek bir yerde tanımlıdır:
hem `reporter.py` hem `modules/exporters/` bu fonksiyonu çağırır.

Daha önce bu kural yalnızca `Reporter.generate()` içinde gömülüydü. Export
katmanı eklenirken kopyalansaydı, ikisinden birinin değişmesi durumunda aynı
capture'ın HTML raporu ile JSON çıktısı FARKLI klasörlere düşerdi -- projede
daha önce `TOOL_VERSION`'ın üç ayrı yere kopyalanıp birbirinden sapmasıyla
aynı hata sınıfı (bkz. config.TOOL_VERSION).
"""
import logging
from pathlib import Path
from typing import Final

import config

logger = logging.getLogger(__name__)

# Kaynak capture'ın üst klasör adı bu kümedeyse çıktılar aynı adlı alt
# klasöre yazılır (samples/malicious/x.pcapng -> reports/malicious/).
_CATEGORY_DIR_NAMES: Final[frozenset[str]] = frozenset({"clean", "malicious"})

# Tanınmayan bir klasörden gelen capture için varsayılan. "clean" seçilmesi
# bir HÜKÜM DEĞİLDİR (dosyanın temiz olduğu iddia edilmiyor); yalnızca
# sınıflandırılmamış çıktıların gideceği varsayılan kovadır -- gerçek risk
# değerlendirmesi raporun kendi risk özetinde yer alır.
_DEFAULT_CATEGORY_DIR: Final[str] = "clean"


def resolve_output_dir(source_file: Path) -> Path:
    """Bir capture'ın çıktılarının yazılacağı dizini döndürür.

    `config.REPORTS_DIR` bilinçli olarak çağrı anında okunur, modül import
    edildiğinde değil: testler bu niteliği monkeypatch ederek çıktıları geçici
    bir dizine yönlendiriyor (bkz. tests/test_reporter.py::isolated_reports_dir).
    Import anında sabitlenseydi testler proje ağacına yazmaya devam ederdi.
    """
    parent_folder_name = source_file.parent.name.lower()
    category = parent_folder_name if parent_folder_name in _CATEGORY_DIR_NAMES else _DEFAULT_CATEGORY_DIR
    return config.REPORTS_DIR / category
