# syntax=docker/dockerfile:1
#
# Automated PCAP Forensic Analysis Tool
#
# Adli analiz aracının taşınabilir çalışma ortamı. Amaç yalnızca "kurulum
# kolaylığı" değil: aynı capture'ın aynı araç sürümüyle, aynı bağımlılıklarla
# analiz edilebilmesi adli tekrarlanabilirliğin (reproducibility) parçasıdır --
# bir bulguya itiraz edildiğinde analizin birebir tekrarlanabilmesi gerekir.
#
# Kullanım (README'de ayrıntılı):
#   docker build -t pcap-forensic .
#   docker run --rm -v "$PWD/samples:/app/samples:ro" -v "$PWD/reports:/app/reports" \
#       pcap-forensic -f samples/malicious/demo_capture.pcapng --format all

# ======================================================================
# 1. AŞAMA: bağımlılıkların kurulumu
# ======================================================================
# Çok aşamalı build: pip ve derleme araçları yalnızca burada bulunur, runtime
# imajına taşınmaz. Bağımlılıklar izole bir venv'e kuruluyor ki ikinci aşamaya
# tek bir dizin kopyalamak yetsin.
FROM python:3.14-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Yalnızca requirements.txt kopyalanıyor: kaynak kod değiştiğinde bu katman
# önbellekten gelir ve bağımlılıklar yeniden kurulmaz.
COPY requirements.txt ./
RUN pip install --requirement requirements.txt

# ======================================================================
# 2. AŞAMA: çalışma zamanı
# ======================================================================
FROM python:3.14-slim AS runtime

# Sürüm build sırasında dışarıdan veriliyor, imaja SABİTLENMİYOR.
# config.TOOL_VERSION bu projede sürümün tek kaynağıdır (bir test main.py,
# reporter.py ve pyproject.toml'un onunla aynı olmasını zorunlu kılar);
# buraya elle bir sürüm yazmak dördüncü bir kopya ve kaçınılmaz bir sapma
# olurdu. Varsayılan "dev" bir kopya değil, dürüst bir "bilinmiyor"dur:
#   docker build --build-arg TOOL_VERSION="$(python -c 'import config; print(config.TOOL_VERSION)')" .
ARG TOOL_VERSION=dev

LABEL org.opencontainers.image.title="Automated PCAP Forensic Analysis Tool" \
      org.opencontainers.image.description="Automated PCAP/PCAPNG forensic analysis for DFIR and network security" \
      org.opencontainers.image.source="https://github.com/salihogz/automated-pcap-forensic" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${TOOL_VERSION}"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Agg: GUI'siz matplotlib backend'i. Kod zaten matplotlib.use("Agg")
    # çağırıyor; burada da verilmesi, backend seçimini import sırasına
    # bağımlı olmaktan çıkarıyor.
    MPLBACKEND=Agg \
    # matplotlib önbelleğini yazılabilir bir yere alır. Konteyner root
    # olmayan (ve `--user` ile HOME'suz da olabilen) bir kullanıcıyla
    # çalıştığı için varsayılan ~/.config/matplotlib yazılamaz; bu ayar
    # verilmezse her çalıştırmada uyarı basılır.
    MPLCONFIGDIR=/tmp/matplotlib

# Root olarak çalıştırmamak, bir güvenlik aracının kendi hijyeninin parçası:
# araç güvenilmeyen girdi (yabancı bir capture dosyası) ayrıştırıyor ve
# ayrıştırıcıda bir zafiyet çıkarsa etki alanı root olmamalı.
# UID/GID 1000 seçildi çünkü tipik Linux masaüstünde ilk kullanıcı budur ve
# volume ile bağlanan reports/ dizinine yazabilmesi gerekir. Host UID'si
# farklıysa README'deki `--user $(id -u):$(id -g)` kullanımı geçerlidir.
RUN groupadd --gid 1000 forensic \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin forensic

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Yalnızca çalışma zamanında gerekenler (test paketi ve geliştirme araçları
# imaja alınmaz -- bkz. .dockerignore).
COPY --chown=forensic:forensic config.py main.py ./
COPY --chown=forensic:forensic modules/ ./modules/
COPY --chown=forensic:forensic templates/ ./templates/
COPY --chown=forensic:forensic samples/ ./samples/

# config.py import edildiğinde bu dizinleri kendisi oluşturmayı dener; önceden
# ve doğru sahiplikle yaratmak, root olmayan kullanıcının /app altında yazma
# denemesinin başarısız olmasını engeller.
#
# reports/ ve logs/ ayrıca 0777: konteyner `--user $(id -u):$(id -g)` ile
# ÇALIŞTIRILABİLMELİ (host UID'si 1000 değilse volume'a yazabilmenin tek yolu
# budur) ve o durumda süreç, imajda hiç tanımlı olmayan rastgele bir UID/GID
# ile koşar. Yalnızca forensic:forensic sahipliği bırakıldığında bu senaryo
# doğrulandığı üzere çöküyordu:
#   PermissionError: [Errno 13] Permission denied: '/app/logs/analysis.log'
# Bu iki dizin host'tan mount edildiğinde zaten host izinleri geçerli olur;
# 0777 yalnızca mount edilmedikleri durumda devreye girer.
RUN mkdir -p /app/reports /app/logs \
    && chown -R forensic:forensic /app \
    && chmod 0777 /app/reports /app/logs

USER forensic

# ENTRYPOINT + boş CMD: konteynerin argümanları doğrudan main.py'ye geçer,
#   docker run pcap-forensic -f samples/... --format all
# Hiç argüman verilmezse main.py samples/ altındaki ilk capture'ı seçer.
ENTRYPOINT ["python", "main.py"]
